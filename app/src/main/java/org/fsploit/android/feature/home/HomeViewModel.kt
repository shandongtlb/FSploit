package org.fsploit.android.feature.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase
import org.fsploit.android.domain.model.PortState

class HomeViewModel(
    private val resourceProvider: ResourceProvider,
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterfaceUseCase: SavePreferredInterfaceUseCase,
    private val probeShell: ProbeShellUseCase,
    private val runHostSweep: RunHostSweepUseCase,
    private val runPortScanUseCase: RunPortScanUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        HomeUiState(
            permissionSummary = resourceProvider.getString(R.string.permission_summary_pending),
            activeTransportLabel = resourceProvider.getString(R.string.transport_unknown),
            shellSummary = resourceProvider.getString(R.string.shell_status_pending),
            scanSummary = resourceProvider.getString(R.string.host_sweep_not_run),
            portScanSummary = resourceProvider.getString(R.string.port_scan_not_run)
        )
    )
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    fun selectSection(section: HomeSection) {
        _uiState.value = _uiState.value.copy(selectedSection = section)
    }

    fun refresh(permissionSummary: String, permissionsGranted: Boolean) {
        viewModelScope.launch(Dispatchers.Default) {
            val overview = loadNetworkOverview()
            val shellStatus = probeShell()
            val currentState = _uiState.value
            val preferredInterfaceName = getPreferredInterface()
                .takeIf { it.isNotBlank() }
                ?: overview.interfaces.firstOrNull()?.name.orEmpty()
            val selectedHostAddress = currentState.selectedHostAddress
                .takeIf { host -> currentState.responsiveHosts.contains(host) }
                ?: currentState.responsiveHosts.firstOrNull().orEmpty()

            _uiState.value = HomeUiState(
                isLoading = false,
                selectedSection = if (permissionsGranted) {
                    currentState.selectedSection
                } else {
                    HomeSection.OVERVIEW
                },
                permissionSummary = permissionSummary,
                activeTransportLabel = overview.activeTransportLabel,
                interfaces = overview.interfaces,
                statusMessage = overview.statusMessage,
                canContinue = permissionsGranted && overview.interfaces.isNotEmpty(),
                shellSummary = shellStatus.summary,
                preferredInterfaceName = preferredInterfaceName,
                scanSummary = currentState.scanSummary.ifBlank {
                    resourceProvider.getString(R.string.host_sweep_not_run)
                },
                scanResults = currentState.scanResults,
                responsiveHosts = currentState.responsiveHosts,
                selectedHostAddress = selectedHostAddress,
                isScanning = false,
                portScanSummary = currentState.portScanSummary.ifBlank {
                    resourceProvider.getString(R.string.port_scan_not_run)
                },
                portScanResults = currentState.portScanResults,
                isPortScanning = false
            )
        }
    }

    fun savePreferredInterface(interfaceName: String) {
        val trimmed = interfaceName.trim()
        savePreferredInterfaceUseCase(trimmed)
        _uiState.value = _uiState.value.copy(preferredInterfaceName = trimmed)
    }

    fun selectHost(hostAddress: String) {
        val trimmed = hostAddress.trim()
        _uiState.value = _uiState.value.copy(
            selectedHostAddress = trimmed
        )
    }

    fun runSweep() {
        val interfaceName = _uiState.value.preferredInterfaceName
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                selectedSection = HomeSection.DISCOVERY,
                isScanning = true,
                scanSummary = resourceProvider.getString(R.string.host_sweep_running),
                portScanSummary = resourceProvider.getString(R.string.port_scan_not_run),
                portScanResults = emptyList(),
                isPortScanning = false
            )

            val report = withContext(Dispatchers.Default) {
                runHostSweep(interfaceName)
            }

            val responsiveHosts = report.responsiveHosts.map { it.hostAddress }
            val selectedHostAddress = _uiState.value.selectedHostAddress
                .takeIf { responsiveHosts.contains(it) }
                ?: responsiveHosts.firstOrNull().orEmpty()

            _uiState.value = _uiState.value.copy(
                isScanning = false,
                scanSummary = report.summary,
                scanResults = report.responsiveHosts.map { "${it.hostAddress}  ${it.finding}" },
                responsiveHosts = responsiveHosts,
                selectedHostAddress = selectedHostAddress,
                portScanSummary = if (selectedHostAddress.isBlank()) {
                    resourceProvider.getString(R.string.port_scan_no_selected_host)
                } else {
                    resourceProvider.getString(R.string.port_scan_ready, selectedHostAddress)
                }
            )
        }
    }

    fun runPortScan() {
        val hostAddress = _uiState.value.selectedHostAddress.trim()
        if (hostAddress.isBlank()) {
            _uiState.value = _uiState.value.copy(
                selectedSection = HomeSection.PORTS,
                portScanSummary = resourceProvider.getString(R.string.port_scan_select_target),
                portScanResults = emptyList()
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                selectedSection = HomeSection.PORTS,
                isPortScanning = true,
                portScanSummary = resourceProvider.getString(R.string.port_scan_running, hostAddress)
            )

            val report = withContext(Dispatchers.Default) {
                runPortScanUseCase(hostAddress)
            }

            _uiState.value = _uiState.value.copy(
                isPortScanning = false,
                portScanSummary = report.summary,
                portScanResults = report.scannedPorts.map { result ->
                    "${result.port.toString().padStart(5, ' ')}  ${result.protocol.padEnd(9, ' ')}  ${portStateLabel(result.state).padEnd(9, ' ')}  ${result.note}"
                }
            )
        }
    }

    private fun portStateLabel(state: PortState): String {
        return when (state) {
            PortState.OPEN -> resourceProvider.getString(R.string.port_state_open)
            PortState.CLOSED -> resourceProvider.getString(R.string.port_state_closed)
            PortState.FILTERED -> resourceProvider.getString(R.string.port_state_filtered)
        }
    }
}
