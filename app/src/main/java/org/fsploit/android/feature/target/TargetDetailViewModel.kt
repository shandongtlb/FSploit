package org.fsploit.android.feature.target

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.HostFingerprinter
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.DeviceRole
import org.fsploit.android.domain.model.HostFingerprint
import org.fsploit.android.domain.model.OsFamily
import org.fsploit.android.domain.model.PortScanConfig
import org.fsploit.android.domain.model.PortScanMode
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.domain.model.PortState
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SavePortScanConfigUseCase
import org.fsploit.android.feature.session.SessionStateHolder

data class TargetDetailUiState(
    val portSpec: String = "",
    val connectTimeoutMs: String = "",
    val parallelism: String = "",
    val portScanSummary: String = "",
    val scannedPortResults: List<PortScanResult> = emptyList(),
    val portScanResults: List<String> = emptyList(),
    val selectedPortResultFilter: PortResultFilter = PortResultFilter.ALL,
    val isPortScanning: Boolean = false,
    val hostFingerprint: String = "",
    val portScanMode: PortScanMode = PortScanMode.NORMAL
)

class TargetDetailViewModel(
    private val resourceProvider: ResourceProvider,
    private val session: SessionStateHolder,
    private val loadPortScanConfig: LoadPortScanConfigUseCase,
    private val savePortScanConfig: SavePortScanConfigUseCase,
    private val runPortScanUseCase: RunPortScanUseCase,
    private val runShellCommandUseCase: RunShellCommandUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        loadPortScanConfig().let { config ->
            TargetDetailUiState(
                portSpec = config.portSpec,
                connectTimeoutMs = config.connectTimeoutMs.toString(),
                parallelism = config.parallelism.toString(),
                portScanSummary = resourceProvider.getString(R.string.port_scan_not_run)
            )
        }
    )
    val uiState: StateFlow<TargetDetailUiState> = _uiState.asStateFlow()

    init {
        // React to the shared selected host: refresh the readiness line, and clear stale results
        // whenever a new host sweep replaces the candidate list.
        var lastHost: String? = null
        var lastHosts: List<String>? = null
        viewModelScope.launch {
            session.state.collect { s ->
                if (lastHosts != null && s.responsiveHosts !== lastHosts && s.responsiveHosts != lastHosts) {
                    _uiState.value = _uiState.value.copy(
                        scannedPortResults = emptyList(),
                        portScanResults = emptyList(),
                        selectedPortResultFilter = PortResultFilter.ALL,
                        hostFingerprint = ""
                    )
                }
                lastHosts = s.responsiveHosts
                if (s.selectedHostAddress != lastHost) {
                    lastHost = s.selectedHostAddress
                    _uiState.value = _uiState.value.copy(
                        portScanSummary = if (s.selectedHostAddress.isBlank()) {
                            resourceProvider.getString(R.string.port_scan_no_selected_host)
                        } else {
                            resourceProvider.getString(R.string.port_scan_ready, s.selectedHostAddress)
                        },
                        hostFingerprint = ""
                    )
                }
            }
        }
    }

    fun updatePortSpec(portSpec: String) {
        _uiState.value = _uiState.value.copy(portSpec = portSpec)
    }

    fun updateConnectTimeout(timeoutMs: String) {
        _uiState.value = _uiState.value.copy(connectTimeoutMs = timeoutMs)
    }

    fun updateParallelism(parallelism: String) {
        _uiState.value = _uiState.value.copy(parallelism = parallelism)
    }

    fun selectPortResultFilter(filter: PortResultFilter) {
        _uiState.value = _uiState.value.copy(selectedPortResultFilter = filter)
    }

    fun selectPortScanMode(mode: PortScanMode) {
        _uiState.value = _uiState.value.copy(portScanMode = mode)
    }

    fun runPortScan() {
        if (!session.value.rootGranted) {
            _uiState.value = _uiState.value.copy(portScanSummary = resourceProvider.getString(R.string.root_gate_blocked))
            return
        }
        val hostAddress = session.value.selectedHostAddress.trim()
        if (hostAddress.isBlank()) {
            _uiState.value = _uiState.value.copy(
                portScanSummary = resourceProvider.getString(R.string.port_scan_select_target),
                scannedPortResults = emptyList(),
                portScanResults = emptyList()
            )
            return
        }

        val config = validatePortScanConfig() ?: return
        savePortScanConfig(config)

        val mode = _uiState.value.portScanMode
        val interfaceName = session.value.preferredInterfaceName

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isPortScanning = true,
                portScanSummary = resourceProvider.getString(R.string.port_scan_running, hostAddress)
            )

            try {
                val report = withContext(Dispatchers.Default) {
                    runPortScanUseCase(hostAddress, config, mode, interfaceName)
                }

                _uiState.value = _uiState.value.copy(
                    isPortScanning = false,
                    portSpec = config.portSpec,
                    connectTimeoutMs = config.connectTimeoutMs.toString(),
                    parallelism = config.parallelism.toString(),
                    portScanSummary = report.summary,
                    scannedPortResults = report.scannedPorts,
                    portScanResults = report.scannedPorts.map { result ->
                        buildString {
                            append(result.port.toString().padStart(5, ' '))
                            append("  ")
                            append(result.protocol.padEnd(9, ' '))
                            append("  ")
                            append(portStateLabel(result.state).padEnd(9, ' '))
                            append("  ")
                            append(result.note)
                        }
                    },
                    hostFingerprint = resourceProvider.getString(R.string.fingerprint_running)
                )

                // nmap's own OS detection (when present) beats the TTL/port heuristic; use it directly.
                if (!report.osInfo.isNullOrBlank()) {
                    _uiState.value = _uiState.value.copy(
                        hostFingerprint = resourceProvider.getString(R.string.fingerprint_os_nmap, report.osInfo)
                    )
                } else if (mode == PortScanMode.UDP) {
                    // The fingerprint heuristic maps TCP port roles; UDP results don't feed it.
                    _uiState.value = _uiState.value.copy(hostFingerprint = "")
                } else {
                    val openPorts = report.scannedPorts
                        .filter { it.state == PortState.OPEN }
                        .map { it.port }
                    val ttl = withContext(Dispatchers.Default) { probeTtl(hostAddress) }
                    val fingerprint = HostFingerprinter.fingerprint(openPorts, ttl)
                    _uiState.value = _uiState.value.copy(
                        hostFingerprint = buildFingerprintSummary(fingerprint)
                    )
                }
            } catch (exception: IllegalArgumentException) {
                _uiState.value = _uiState.value.copy(
                    isPortScanning = false,
                    portScanSummary = exception.message
                        ?: resourceProvider.getString(R.string.port_scan_config_invalid),
                    scannedPortResults = emptyList(),
                    portScanResults = emptyList(),
                    hostFingerprint = ""
                )
            }
        }
    }

    /** Best-effort single-shot ping to read the reply TTL for OS-family heuristics. */
    private suspend fun probeTtl(hostAddress: String): Int? {
        val command = "ping -c 1 -W 1 ${singleQuote(hostAddress)}"
        val result = runShellCommandUseCase(
            command = command,
            asRoot = session.value.rootGranted,
            timeoutMs = TTL_PROBE_TIMEOUT_MS
        )
        val match = Regex("(?i)ttl=(\\d+)").find(result.output) ?: return null
        return match.groupValues[1].toIntOrNull()
    }

    private fun buildFingerprintSummary(fingerprint: HostFingerprint): String {
        val ttlLabel = fingerprint.ttl
            ?.let { resourceProvider.getString(R.string.fingerprint_ttl, it) }
            ?: resourceProvider.getString(R.string.fingerprint_ttl_unknown)
        val osLine = resourceProvider.getString(
            R.string.fingerprint_os,
            resourceProvider.getString(osFamilyLabelRes(fingerprint.osFamily)),
            ttlLabel
        )
        val rolesLine = if (fingerprint.roles.isEmpty()) {
            resourceProvider.getString(R.string.fingerprint_roles_none)
        } else {
            resourceProvider.getString(
                R.string.fingerprint_roles,
                fingerprint.roles.joinToString("、") { resourceProvider.getString(roleLabelRes(it)) }
            )
        }
        return "$osLine\n$rolesLine"
    }

    private fun osFamilyLabelRes(osFamily: OsFamily): Int = when (osFamily) {
        OsFamily.LINUX_UNIX -> R.string.os_family_linux
        OsFamily.WINDOWS -> R.string.os_family_windows
        OsFamily.NETWORK_DEVICE -> R.string.os_family_network
        OsFamily.APPLE -> R.string.os_family_apple
        OsFamily.UNKNOWN -> R.string.os_family_unknown
    }

    private fun roleLabelRes(role: DeviceRole): Int = when (role) {
        DeviceRole.REMOTE_DESKTOP -> R.string.role_remote_desktop
        DeviceRole.SMB_SHARE -> R.string.role_smb
        DeviceRole.SSH -> R.string.role_ssh
        DeviceRole.IP_CAMERA -> R.string.role_camera
        DeviceRole.PRINTER -> R.string.role_printer
        DeviceRole.NAS -> R.string.role_nas
        DeviceRole.DATABASE -> R.string.role_database
        DeviceRole.IOT_TELNET -> R.string.role_iot_telnet
        DeviceRole.ROUTER_DNS -> R.string.role_router
        DeviceRole.APPLE_DEVICE -> R.string.role_apple
        DeviceRole.WEB_SERVER -> R.string.role_web
    }

    private fun singleQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

    private fun validatePortScanConfig(): PortScanConfig? {
        val state = _uiState.value
        val portSpec = state.portSpec.trim()
        if (portSpec.isBlank()) {
            _uiState.value = state.copy(
                portScanSummary = resourceProvider.getString(R.string.port_spec_empty),
                portScanResults = emptyList()
            )
            return null
        }

        val timeoutMs = state.connectTimeoutMs.trim().toIntOrNull()
        if (timeoutMs == null || timeoutMs !in 100..5000) {
            _uiState.value = state.copy(
                portScanSummary = resourceProvider.getString(R.string.port_scan_timeout_invalid),
                portScanResults = emptyList()
            )
            return null
        }

        val parallelism = state.parallelism.trim().toIntOrNull()
        if (parallelism == null || parallelism !in 1..64) {
            _uiState.value = state.copy(
                portScanSummary = resourceProvider.getString(R.string.port_scan_parallelism_invalid),
                portScanResults = emptyList()
            )
            return null
        }

        return PortScanConfig(
            portSpec = portSpec,
            connectTimeoutMs = timeoutMs,
            parallelism = parallelism
        )
    }

    private fun portStateLabel(state: PortState): String {
        return when (state) {
            PortState.OPEN -> resourceProvider.getString(R.string.port_state_open)
            PortState.CLOSED -> resourceProvider.getString(R.string.port_state_closed)
            PortState.FILTERED -> resourceProvider.getString(R.string.port_state_filtered)
        }
    }

    companion object {
        private const val TTL_PROBE_TIMEOUT_MS = 3000L
    }
}
