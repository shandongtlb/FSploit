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
import org.fsploit.android.domain.model.MsfJobInfo
import org.fsploit.android.domain.model.MsfRpcConfig
import org.fsploit.android.domain.model.MsfSessionInfo
import org.fsploit.android.domain.usecase.LoadMsfOverviewUseCase
import org.fsploit.android.domain.usecase.LoadMsfRpcConfigUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SaveMsfRpcConfigUseCase
import org.fsploit.android.feature.session.SessionStateHolder

data class MsfUiState(
    val msfRpcConfig: MsfRpcConfig = MsfRpcConfig(),
    val msfSummary: String = "",
    val msfSettingsSummary: String = "",
    val isSavingMsfRpcConfig: Boolean = false,
    val msfLaunchSummary: String = "",
    val msfLaunchOutput: String = "",
    val isLaunchingMsfRpc: Boolean = false,
    val msfConnected: Boolean = false,
    val msfFrameworkVersion: String = "",
    val msfRubyVersion: String = "",
    val msfApiVersion: String = "",
    val msfSessions: List<MsfSessionInfo> = emptyList(),
    val msfJobs: List<MsfJobInfo> = emptyList(),
    val isRefreshingMsf: Boolean = false
)

class MsfViewModel(
    private val resourceProvider: ResourceProvider,
    private val session: SessionStateHolder,
    private val loadMsfRpcConfigUseCase: LoadMsfRpcConfigUseCase,
    private val loadMsfOverviewUseCase: LoadMsfOverviewUseCase,
    private val saveMsfRpcConfigUseCase: SaveMsfRpcConfigUseCase,
    private val runShellCommandUseCase: RunShellCommandUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        MsfUiState(
            msfSummary = resourceProvider.getString(R.string.msf_summary_pending),
            msfSettingsSummary = resourceProvider.getString(R.string.msf_settings_idle),
            msfLaunchSummary = resourceProvider.getString(R.string.msf_launch_idle)
        )
    )
    val uiState: StateFlow<MsfUiState> = _uiState.asStateFlow()

    private var configLoaded = false

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

    fun updateMsfRpcLaunchCommand(value: String) {
        _uiState.value = _uiState.value.copy(msfRpcConfig = _uiState.value.msfRpcConfig.copy(launchCommand = value))
    }

    fun applyMsfMsgrpcPreset() {
        val current = _uiState.value.msfRpcConfig
        _uiState.value = _uiState.value.copy(
            msfRpcConfig = current.copy(
                host = "127.0.0.1",
                port = 55552,
                username = "msf",
                password = "msf",
                useSsl = false,
                launchCommand = "nh -r \"msfconsole -qx 'load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=msf SSL=false'\""
            ),
            msfSettingsSummary = resourceProvider.getString(R.string.msf_preset_msgrpc_applied)
        )
    }

    fun applyMsfMsfrpcdPreset() {
        val current = _uiState.value.msfRpcConfig
        _uiState.value = _uiState.value.copy(
            msfRpcConfig = current.copy(
                host = "127.0.0.1",
                port = 55553,
                username = "msf",
                password = "msf",
                useSsl = true,
                launchCommand = "nh -r \"msfrpcd -P msf -U msf -a 127.0.0.1 -p 55553 -S\""
            ),
            msfSettingsSummary = resourceProvider.getString(R.string.msf_preset_msfrpcd_applied)
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

    fun launchMsfRpcCommand() {
        if (!session.value.rootGranted) {
            _uiState.value = _uiState.value.copy(msfLaunchSummary = resourceProvider.getString(R.string.root_gate_blocked))
            return
        }

        val state = _uiState.value
        val command = state.msfRpcConfig.launchCommand.trim()
        if (command.isEmpty()) {
            _uiState.value = state.copy(
                msfLaunchSummary = resourceProvider.getString(R.string.msf_launch_command_empty),
                msfLaunchOutput = ""
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = state.copy(
                isLaunchingMsfRpc = true,
                msfLaunchSummary = resourceProvider.getString(R.string.msf_launch_running)
            )

            val result = withContext(Dispatchers.Default) {
                runShellCommandUseCase(command = command, asRoot = true, timeoutMs = MSF_LAUNCH_TIMEOUT_MS)
            }

            _uiState.value = _uiState.value.copy(
                isLaunchingMsfRpc = false,
                msfLaunchSummary = result.summary,
                msfLaunchOutput = result.output.ifBlank {
                    resourceProvider.getString(R.string.shell_command_no_output)
                }
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

    private fun buildMsfSummary(config: MsfRpcConfig): String {
        return resourceProvider.getString(
            if (config.launchCommand.isBlank()) {
                R.string.msf_summary_remote
            } else {
                R.string.msf_summary_local_launch
            },
            config.host,
            config.port,
            resourceProvider.getString(
                if (config.useSsl) R.string.msf_ssl_enabled else R.string.msf_ssl_disabled
            )
        )
    }

    companion object {
        private const val MSF_LAUNCH_TIMEOUT_MS = 8000L
    }
}
