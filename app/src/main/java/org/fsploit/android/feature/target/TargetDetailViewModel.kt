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
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.PortScanConfig
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.domain.model.PortState
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
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
    val isPortScanning: Boolean = false
)

class TargetDetailViewModel(
    private val resourceProvider: ResourceProvider,
    private val session: SessionStateHolder,
    private val loadPortScanConfig: LoadPortScanConfigUseCase,
    private val savePortScanConfig: SavePortScanConfigUseCase,
    private val runPortScanUseCase: RunPortScanUseCase
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
                        selectedPortResultFilter = PortResultFilter.ALL
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
                        }
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

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isPortScanning = true,
                portScanSummary = resourceProvider.getString(R.string.port_scan_running, hostAddress)
            )

            try {
                val report = withContext(Dispatchers.Default) {
                    runPortScanUseCase(hostAddress, config)
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
                    }
                )
            } catch (exception: IllegalArgumentException) {
                _uiState.value = _uiState.value.copy(
                    isPortScanning = false,
                    portScanSummary = exception.message
                        ?: resourceProvider.getString(R.string.port_scan_config_invalid),
                    scannedPortResults = emptyList(),
                    portScanResults = emptyList()
                )
            }
        }
    }

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
}
