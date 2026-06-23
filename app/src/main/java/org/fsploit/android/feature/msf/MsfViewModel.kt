package org.fsploit.android.feature.msf

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
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
import org.fsploit.android.domain.usecase.ProbeMsfConnectionUseCase
import org.fsploit.android.domain.usecase.ReadMsfSessionUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SaveMsfRpcConfigUseCase
import org.fsploit.android.domain.usecase.StopMsfJobUseCase
import org.fsploit.android.domain.usecase.StopMsfSessionUseCase
import org.fsploit.android.domain.usecase.WriteMsfSessionUseCase
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
    val isRefreshingMsf: Boolean = false,
    val msfActionSummary: String = "",
    val isRunningMsfAction: Boolean = false,
    val consoleSessionId: String = "",
    val consoleOutput: String = "",
    val consoleSummary: String = "",
    val isConsoleBusy: Boolean = false
)

class MsfViewModel(
    private val resourceProvider: ResourceProvider,
    private val session: SessionStateHolder,
    private val loadMsfRpcConfigUseCase: LoadMsfRpcConfigUseCase,
    private val loadMsfOverviewUseCase: LoadMsfOverviewUseCase,
    private val saveMsfRpcConfigUseCase: SaveMsfRpcConfigUseCase,
    private val runShellCommandUseCase: RunShellCommandUseCase,
    private val probeMsfConnectionUseCase: ProbeMsfConnectionUseCase,
    private val stopMsfSessionUseCase: StopMsfSessionUseCase,
    private val stopMsfJobUseCase: StopMsfJobUseCase,
    private val writeMsfSessionUseCase: WriteMsfSessionUseCase,
    private val readMsfSessionUseCase: ReadMsfSessionUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        MsfUiState(
            msfSummary = resourceProvider.getString(R.string.msf_summary_pending),
            msfSettingsSummary = resourceProvider.getString(R.string.msf_settings_idle),
            msfLaunchSummary = resourceProvider.getString(R.string.msf_launch_idle),
            msfActionSummary = resourceProvider.getString(R.string.msf_action_idle),
            consoleSummary = resourceProvider.getString(R.string.msf_console_idle)
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
                // msfconsole does not self-daemonize, so detach it with setsid + & to survive the
                // launch shell being reaped; FSploit then polls core.version for readiness.
                launchCommand = "setsid nh -r \"msfconsole -qx 'load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=msf SSL=false'\" </dev/null >/dev/null 2>&1 &"
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
                // msfrpcd daemonizes itself; detach anyway so a reaped launch shell never takes it down.
                launchCommand = "setsid nh -r \"msfrpcd -P msf -U msf -a 127.0.0.1 -p 55553 -S\" </dev/null >/dev/null 2>&1 &"
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
            _uiState.value = _uiState.value.copy(
                isLaunchingMsfRpc = true,
                msfLaunchSummary = resourceProvider.getString(R.string.msf_launch_running)
            )

            val result = withContext(Dispatchers.Default) {
                runShellCommandUseCase(command = command, asRoot = true, timeoutMs = MSF_LAUNCH_TIMEOUT_MS)
            }

            _uiState.value = _uiState.value.copy(
                msfLaunchOutput = result.output.ifBlank {
                    resourceProvider.getString(R.string.shell_command_no_output)
                },
                msfLaunchSummary = resourceProvider.getString(R.string.msf_launch_probing)
            )

            // The daemon comes up asynchronously, so trust core.version answering rather than the
            // launch shell's exit code (a foreground RPC server never exits on its own).
            val config = _uiState.value.msfRpcConfig
            val reachable = pollReachable(config)

            _uiState.value = _uiState.value.copy(
                isLaunchingMsfRpc = false,
                msfLaunchSummary = resourceProvider.getString(
                    if (reachable) R.string.msf_launch_reachable else R.string.msf_launch_unreachable
                )
            )

            if (reachable) {
                refreshMsfOverview()
            }
        }
    }

    private suspend fun pollReachable(config: MsfRpcConfig): Boolean {
        for (attempt in 0 until MSF_LAUNCH_PROBE_ATTEMPTS) {
            val reachable = withContext(Dispatchers.Default) { probeMsfConnectionUseCase(config) }
            if (reachable) {
                return true
            }
            delay(MSF_LAUNCH_PROBE_INTERVAL_MS)
        }
        return false
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

    fun updateConsoleSessionId(value: String) {
        _uiState.value = _uiState.value.copy(consoleSessionId = value.trim())
    }

    fun sendConsoleCommand(command: String) {
        val id = _uiState.value.consoleSessionId.trim()
        if (id.isEmpty()) {
            _uiState.value = _uiState.value.copy(consoleSummary = resourceProvider.getString(R.string.msf_action_id_required))
            return
        }
        if (command.trim().isEmpty()) {
            _uiState.value = _uiState.value.copy(consoleSummary = resourceProvider.getString(R.string.msf_console_command_required))
            return
        }
        if (!validateConfigForConsole()) {
            return
        }

        val type = sessionTypeFor(id)
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isConsoleBusy = true,
                consoleSummary = resourceProvider.getString(R.string.msf_console_sending),
                consoleOutput = appendConsole(_uiState.value.consoleOutput, "> ${command.trim()}")
            )

            val summary = withContext(Dispatchers.Default) {
                val config = _uiState.value.msfRpcConfig
                val write = writeMsfSessionUseCase(config, id, type, command.trim())
                if (!write.success) {
                    return@withContext write.message
                }
                // Give the session a moment to produce output before the first read.
                delay(MSF_CONSOLE_READ_DELAY_MS)
                val read = readMsfSessionUseCase(config, id, type)
                if (read.success) {
                    if (read.data.isNotBlank()) {
                        appendOutput(read.data)
                    }
                    resourceProvider.getString(R.string.msf_console_sent)
                } else {
                    read.message
                }
            }

            _uiState.value = _uiState.value.copy(isConsoleBusy = false, consoleSummary = summary)
        }
    }

    fun readConsole() {
        val id = _uiState.value.consoleSessionId.trim()
        if (id.isEmpty()) {
            _uiState.value = _uiState.value.copy(consoleSummary = resourceProvider.getString(R.string.msf_action_id_required))
            return
        }
        if (!validateConfigForConsole()) {
            return
        }

        val type = sessionTypeFor(id)
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isConsoleBusy = true,
                consoleSummary = resourceProvider.getString(R.string.msf_console_reading)
            )
            val summary = withContext(Dispatchers.Default) {
                val read = readMsfSessionUseCase(_uiState.value.msfRpcConfig, id, type)
                if (read.success) {
                    if (read.data.isNotBlank()) {
                        appendOutput(read.data)
                        resourceProvider.getString(R.string.msf_console_read_ok)
                    } else {
                        resourceProvider.getString(R.string.msf_console_read_empty)
                    }
                } else {
                    read.message
                }
            }
            _uiState.value = _uiState.value.copy(isConsoleBusy = false, consoleSummary = summary)
        }
    }

    fun clearConsole() {
        _uiState.value = _uiState.value.copy(
            consoleOutput = "",
            consoleSummary = resourceProvider.getString(R.string.msf_console_cleared)
        )
    }

    private fun appendOutput(data: String) {
        _uiState.value = _uiState.value.copy(
            consoleOutput = appendConsole(_uiState.value.consoleOutput, data.trimEnd('\n'))
        )
    }

    private fun appendConsole(current: String, addition: String): String {
        val combined = if (current.isEmpty()) addition else "$current\n$addition"
        return if (combined.length > MSF_CONSOLE_MAX_CHARS) {
            combined.takeLast(MSF_CONSOLE_MAX_CHARS)
        } else {
            combined
        }
    }

    private fun sessionTypeFor(id: String): String =
        _uiState.value.msfSessions.firstOrNull { it.id == id }?.type.orEmpty()

    private fun validateConfigForCall(): Boolean = validateConfig { _uiState.value.copy(msfActionSummary = it) }

    private fun validateConfigForConsole(): Boolean = validateConfig { _uiState.value.copy(consoleSummary = it) }

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
        private const val MSF_LAUNCH_TIMEOUT_MS = 10_000L
        private const val MSF_LAUNCH_PROBE_ATTEMPTS = 12
        private const val MSF_LAUNCH_PROBE_INTERVAL_MS = 3_000L
        private const val MSF_CONSOLE_READ_DELAY_MS = 600L
        private const val MSF_CONSOLE_MAX_CHARS = 20_000
    }
}
