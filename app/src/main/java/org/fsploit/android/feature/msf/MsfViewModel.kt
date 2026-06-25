package org.fsploit.android.feature.msf

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.msf.MsfPayloads
import org.fsploit.android.data.msf.MsfScanners
import org.fsploit.android.domain.model.MsfJobInfo
import org.fsploit.android.domain.model.MsfRpcConfig
import org.fsploit.android.domain.model.MsfSessionInfo
import org.fsploit.android.domain.usecase.EnsureMsgrpcScriptUseCase
import org.fsploit.android.domain.usecase.LoadMsfOverviewUseCase
import org.fsploit.android.domain.usecase.LoadMsfRpcConfigUseCase
import org.fsploit.android.domain.usecase.PushMsfTargetUseCase
import org.fsploit.android.domain.usecase.RunMsfScanUseCase
import org.fsploit.android.domain.usecase.SaveMsfRpcConfigUseCase
import org.fsploit.android.domain.usecase.StartMsfHandlerUseCase
import org.fsploit.android.domain.usecase.StopMsfJobUseCase
import org.fsploit.android.domain.usecase.StopMsfSessionUseCase
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionStateHolder

data class MsfUiState(
    val msfRpcConfig: MsfRpcConfig = MsfRpcConfig(),
    val msfSummary: String = "",
    val msfSettingsSummary: String = "",
    val isSavingMsfRpcConfig: Boolean = false,
    val msfConnected: Boolean = false,
    val msfFrameworkVersion: String = "",
    val msfRubyVersion: String = "",
    val msfApiVersion: String = "",
    val msfSessions: List<MsfSessionInfo> = emptyList(),
    val msfJobs: List<MsfJobInfo> = emptyList(),
    val isRefreshingMsf: Boolean = false,
    // Handoff (B): push selected host to the shared msgrpc instance via core.setg RHOSTS.
    val pushTargetSummary: String = "",
    val isPushingTarget: Boolean = false,
    val msfActionSummary: String = "",
    val isRunningMsfAction: Boolean = false,
    // Vuln scan: run a curated auxiliary scanner against the selected host in the shared instance.
    val scanModulePath: String = MsfScanners.COMMON.first().modulePath,
    val scanRhosts: String = "",
    val scanOutput: String = "",
    val scanSummary: String = "",
    val isScanning: Boolean = false,
    // Listener + payload (A)
    val payload: String = MsfPayloads.COMMON.first(),
    val lhost: String = "",
    val lport: String = "4444",
    val handlerSummary: String = "",
    val isStartingHandler: Boolean = false
)

/**
 * MSF screen ViewModel — a thin "skin" over the shared msgrpc instance. The app never launches MSF;
 * it connects to the operator's interactive `load msgrpc` console (direction B) and offers one-tap
 * actions that push context/work into that same instance: set RHOSTS, run an auxiliary scanner,
 * start a handler, run an exploit. Heavy interaction stays in the NetHunter terminal.
 */
class MsfViewModel(
    private val resourceProvider: ResourceProvider,
    private val session: SessionStateHolder,
    private val loadMsfRpcConfigUseCase: LoadMsfRpcConfigUseCase,
    private val loadMsfOverviewUseCase: LoadMsfOverviewUseCase,
    private val saveMsfRpcConfigUseCase: SaveMsfRpcConfigUseCase,
    private val stopMsfSessionUseCase: StopMsfSessionUseCase,
    private val stopMsfJobUseCase: StopMsfJobUseCase,
    private val startMsfHandlerUseCase: StartMsfHandlerUseCase,
    private val runMsfScanUseCase: RunMsfScanUseCase,
    private val pushMsfTargetUseCase: PushMsfTargetUseCase,
    private val ensureMsgrpcScriptUseCase: EnsureMsgrpcScriptUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        MsfUiState(
            msfSummary = resourceProvider.getString(R.string.msf_summary_pending),
            msfSettingsSummary = resourceProvider.getString(R.string.msf_settings_idle),
            msfActionSummary = resourceProvider.getString(R.string.msf_action_idle),
            pushTargetSummary = resourceProvider.getString(R.string.msf_push_target_idle),
            scanSummary = resourceProvider.getString(R.string.msf_scan_idle),
            handlerSummary = resourceProvider.getString(R.string.msf_handler_idle)
        )
    )
    val uiState: StateFlow<MsfUiState> = _uiState.asStateFlow()

    private var configLoaded = false
    private var helperEnsured = false

    // Track the last auto-seeded values so we only overwrite fields the user has not edited.
    private var previousLocalIp = ""
    private var previousSelectedHost = ""

    init {
        // Seed LHOST from this device's interface IP and RHOSTS from the host workbench selection,
        // mirroring how MitmViewModel keeps its gateway input in sync with shared session state.
        viewModelScope.launch {
            session.state.collect(::onSessionChanged)
        }
    }

    private fun onSessionChanged(state: SessionState) {
        val localIp = state.interfaces
            .firstOrNull { it.name == state.preferredInterfaceName }
            ?.primaryAddress
            .orEmpty()
        val selectedHost = state.selectedHostAddress.trim()
        val current = _uiState.value

        val lhost = if (current.lhost.isBlank() || current.lhost == previousLocalIp) localIp else current.lhost
        val scanRhosts =
            if (current.scanRhosts.isBlank() || current.scanRhosts == previousSelectedHost) selectedHost else current.scanRhosts

        if (localIp.isNotBlank()) previousLocalIp = localIp
        if (selectedHost.isNotBlank()) previousSelectedHost = selectedHost

        _uiState.value = current.copy(
            lhost = lhost,
            scanRhosts = scanRhosts
        )
    }

    /** Loads the persisted RPC endpoint the first time the screen is shown, without clobbering edits. */
    fun refresh() {
        if (!configLoaded) {
            configLoaded = true
            val stored = loadMsfRpcConfigUseCase()
            _uiState.value = _uiState.value.copy(
                msfRpcConfig = stored,
                msfSummary = buildMsfSummary(stored)
            )
        } else {
            _uiState.value = _uiState.value.copy(msfSummary = buildMsfSummary(_uiState.value.msfRpcConfig))
        }
        ensureHelperScript()
    }

    /**
     * Re-drop the `msfstart` helper into the Kali chroot if it is missing (a kalifs reinstall wipes
     * it). Best-effort and silent unless we actually had to install it; needs root to write.
     */
    private fun ensureHelperScript() {
        if (helperEnsured || !session.value.rootGranted) {
            return
        }
        helperEnsured = true
        viewModelScope.launch {
            val installed = withContext(Dispatchers.Default) { ensureMsgrpcScriptUseCase() }
            if (installed) {
                _uiState.value = _uiState.value.copy(
                    msfSettingsSummary = resourceProvider.getString(R.string.msf_helper_installed)
                )
            }
        }
    }

    fun updateMsfRpcHost(value: String) {
        _uiState.value = _uiState.value.copy(msfRpcConfig = _uiState.value.msfRpcConfig.copy(host = value.trim()))
    }

    fun updateMsfRpcPort(value: String) {
        val parsed = value.trim().toIntOrNull() ?: 0
        _uiState.value = _uiState.value.copy(msfRpcConfig = _uiState.value.msfRpcConfig.copy(port = parsed))
    }

    fun updateMsfRpcUsername(value: String) {
        _uiState.value = _uiState.value.copy(msfRpcConfig = _uiState.value.msfRpcConfig.copy(username = value))
    }

    fun updateMsfRpcPassword(value: String) {
        _uiState.value = _uiState.value.copy(msfRpcConfig = _uiState.value.msfRpcConfig.copy(password = value))
    }

    fun updateMsfRpcUseSsl(value: Boolean) {
        _uiState.value = _uiState.value.copy(msfRpcConfig = _uiState.value.msfRpcConfig.copy(useSsl = value))
    }

    /**
     * Direction B: the app never launches MSF. The operator keeps an interactive `msfconsole +
     * load msgrpc` open in the NetHunter terminal (one shared framework instance) and FSploit only
     * connects to it, so launchCommand is intentionally left blank.
     */
    fun applyMsfMsgrpcPreset() {
        val current = _uiState.value.msfRpcConfig
        _uiState.value = _uiState.value.copy(
            msfRpcConfig = current.copy(
                host = "127.0.0.1",
                port = 55552,
                username = "msf",
                password = "msf",
                useSsl = false,
                launchCommand = ""
            ),
            msfSettingsSummary = resourceProvider.getString(R.string.msf_preset_msgrpc_applied)
        )
    }

    fun saveMsfRpcConfig() {
        val config = _uiState.value.msfRpcConfig
        if (config.host.trim().isEmpty()) {
            _uiState.value = _uiState.value.copy(msfSettingsSummary = resourceProvider.getString(R.string.msf_host_required))
            return
        }
        if (config.port !in 1..65535) {
            _uiState.value = _uiState.value.copy(msfSettingsSummary = resourceProvider.getString(R.string.msf_port_invalid))
            return
        }
        if (config.username.trim().isEmpty() || config.password.isEmpty()) {
            _uiState.value = _uiState.value.copy(msfSettingsSummary = resourceProvider.getString(R.string.msf_credentials_required))
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isSavingMsfRpcConfig = true,
                msfSettingsSummary = resourceProvider.getString(R.string.msf_settings_saving)
            )

            withContext(Dispatchers.Default) {
                saveMsfRpcConfigUseCase(
                    config.copy(
                        host = config.host.trim(),
                        username = config.username.trim(),
                        launchCommand = config.launchCommand.trim()
                    )
                )
            }

            _uiState.value = _uiState.value.copy(
                isSavingMsfRpcConfig = false,
                msfSummary = buildMsfSummary(_uiState.value.msfRpcConfig),
                msfSettingsSummary = resourceProvider.getString(R.string.msf_settings_saved)
            )
        }
    }

    fun refreshMsfOverview() {
        val state = _uiState.value
        val config = state.msfRpcConfig
        if (config.host.trim().isEmpty()) {
            _uiState.value = state.copy(msfSummary = resourceProvider.getString(R.string.msf_host_required))
            return
        }
        if (config.port !in 1..65535) {
            _uiState.value = state.copy(msfSummary = resourceProvider.getString(R.string.msf_port_invalid))
            return
        }
        if (config.username.trim().isEmpty() || config.password.isEmpty()) {
            _uiState.value = state.copy(msfSummary = resourceProvider.getString(R.string.msf_credentials_required))
            return
        }

        viewModelScope.launch {
            _uiState.value = state.copy(
                isRefreshingMsf = true,
                msfSummary = resourceProvider.getString(R.string.msf_probe_running)
            )

            val overview = withContext(Dispatchers.Default) {
                loadMsfOverviewUseCase(config)
            }

            _uiState.value = _uiState.value.copy(
                isRefreshingMsf = false,
                msfConnected = overview.connected,
                msfFrameworkVersion = overview.frameworkVersion,
                msfRubyVersion = overview.rubyVersion,
                msfApiVersion = overview.apiVersion,
                msfSessions = overview.sessions,
                msfJobs = overview.jobs,
                msfSummary = overview.summary
            )
        }
    }

    /** Handoff (B): push the workbench's selected host into the shared instance as RHOSTS/RHOST. */
    fun pushSelectedHostToMsf() {
        val host = session.value.selectedHostAddress.trim()
        if (host.isEmpty()) {
            _uiState.value = _uiState.value.copy(
                pushTargetSummary = resourceProvider.getString(R.string.msf_push_target_no_host)
            )
            return
        }
        if (!validateConfig { _uiState.value.copy(pushTargetSummary = it) }) {
            return
        }
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isPushingTarget = true,
                pushTargetSummary = resourceProvider.getString(R.string.msf_push_target_running, host)
            )
            val message = withContext(Dispatchers.Default) {
                pushMsfTargetUseCase(_uiState.value.msfRpcConfig, host).message
            }
            _uiState.value = _uiState.value.copy(isPushingTarget = false, pushTargetSummary = message)
        }
    }

    // ---- Vuln scan ----

    fun updateScanModule(modulePath: String) {
        _uiState.value = _uiState.value.copy(scanModulePath = modulePath.trim())
    }

    fun updateScanRhosts(value: String) {
        _uiState.value = _uiState.value.copy(scanRhosts = value.trim())
    }

    fun runVulnScan() {
        val state = _uiState.value
        val rhosts = state.scanRhosts.ifBlank { session.value.selectedHostAddress.trim() }
        if (rhosts.isBlank()) {
            _uiState.value = state.copy(scanSummary = resourceProvider.getString(R.string.msf_scan_no_host))
            return
        }
        if (state.scanModulePath.isBlank()) {
            _uiState.value = state.copy(scanSummary = resourceProvider.getString(R.string.msf_scan_module_required))
            return
        }
        if (!validateConfig { _uiState.value.copy(scanSummary = it) }) {
            return
        }
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isScanning = true,
                scanSummary = resourceProvider.getString(R.string.msf_scan_running, state.scanModulePath),
                scanOutput = ""
            )
            val result = withContext(Dispatchers.Default) {
                runMsfScanUseCase(_uiState.value.msfRpcConfig, state.scanModulePath, rhosts)
            }
            _uiState.value = _uiState.value.copy(
                isScanning = false,
                scanSummary = result.message,
                scanOutput = result.data
            )
            // A scanner can open a session/job in the shared instance; surface it in the list.
            refreshMsfOverview()
        }
    }

    fun stopSession(sessionId: String) {
        val id = sessionId.trim()
        if (id.isEmpty()) {
            _uiState.value = _uiState.value.copy(msfActionSummary = resourceProvider.getString(R.string.msf_action_id_required))
            return
        }
        runMsfAction { stopMsfSessionUseCase(_uiState.value.msfRpcConfig, id).message }
    }

    fun stopJob(jobId: String) {
        val id = jobId.trim()
        if (id.isEmpty()) {
            _uiState.value = _uiState.value.copy(msfActionSummary = resourceProvider.getString(R.string.msf_action_id_required))
            return
        }
        runMsfAction { stopMsfJobUseCase(_uiState.value.msfRpcConfig, id).message }
    }

    private fun runMsfAction(action: () -> String) {
        if (!validateConfigForCall()) {
            return
        }
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isRunningMsfAction = true,
                msfActionSummary = resourceProvider.getString(R.string.msf_action_running)
            )
            val message = withContext(Dispatchers.Default) { action() }
            _uiState.value = _uiState.value.copy(
                isRunningMsfAction = false,
                msfActionSummary = message
            )
            refreshMsfOverview()
        }
    }

    // ---- Listener + payload (A) ----

    fun updatePayload(value: String) {
        _uiState.value = _uiState.value.copy(payload = value)
    }

    fun updateLhost(value: String) {
        _uiState.value = _uiState.value.copy(lhost = value.trim())
    }

    fun updateLport(value: String) {
        _uiState.value = _uiState.value.copy(lport = value.trim())
    }

    fun startHandler() {
        val state = _uiState.value
        if (state.payload.isBlank()) {
            _uiState.value = state.copy(handlerSummary = resourceProvider.getString(R.string.msf_handler_payload_required))
            return
        }
        if (!validateConfig { _uiState.value.copy(handlerSummary = it) }) {
            return
        }
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isStartingHandler = true,
                handlerSummary = resourceProvider.getString(R.string.msf_handler_starting)
            )
            val message = withContext(Dispatchers.Default) {
                startMsfHandlerUseCase(_uiState.value.msfRpcConfig, state.payload, state.lhost, state.lport).message
            }
            _uiState.value = _uiState.value.copy(isStartingHandler = false, handlerSummary = message)
            refreshMsfOverview()
        }
    }

    private fun validateConfigForCall(): Boolean = validateConfig { _uiState.value.copy(msfActionSummary = it) }

    private inline fun validateConfig(onError: (String) -> MsfUiState): Boolean {
        val config = _uiState.value.msfRpcConfig
        val error = when {
            config.host.trim().isEmpty() -> resourceProvider.getString(R.string.msf_host_required)
            config.port !in 1..65535 -> resourceProvider.getString(R.string.msf_port_invalid)
            config.username.trim().isEmpty() || config.password.isEmpty() ->
                resourceProvider.getString(R.string.msf_credentials_required)
            else -> null
        }
        return if (error == null) {
            true
        } else {
            _uiState.value = onError(error)
            false
        }
    }

    private fun buildMsfSummary(config: MsfRpcConfig): String {
        return resourceProvider.getString(
            R.string.msf_summary_remote,
            config.host,
            config.port,
            resourceProvider.getString(
                if (config.useSsl) R.string.msf_ssl_enabled else R.string.msf_ssl_disabled
            )
        )
    }
}
