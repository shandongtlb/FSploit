package org.fsploit.android.feature.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase

class HomeViewModel(
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterfaceUseCase: SavePreferredInterfaceUseCase,
    private val probeShell: ProbeShellUseCase,
    private val runHostSweep: RunHostSweepUseCase,
    private val runPortScanUseCase: RunPortScanUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

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
                permissionSummary = permissionSummary,
                activeTransportLabel = overview.activeTransportLabel,
                interfaces = overview.interfaces,
                statusMessage = overview.statusMessage,
                canContinue = permissionsGranted && overview.interfaces.isNotEmpty(),
                shellSummary = shellStatus.summary,
                preferredInterfaceName = preferredInterfaceName,
                scanSummary = currentState.scanSummary,
                scanResults = currentState.scanResults,
                responsiveHosts = currentState.responsiveHosts,
                selectedHostAddress = selectedHostAddress,
                isScanning = false,
                portScanSummary = currentState.portScanSummary,
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
                isScanning = true,
                scanSummary = "Running host sweep...",
                portScanSummary = "No port scan has been run yet.",
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
                    "No responsive host is selected for port scanning."
                } else {
                    "Ready to scan common ports on $selectedHostAddress."
                }
            )
        }
    }

    fun runPortScan() {
        val hostAddress = _uiState.value.selectedHostAddress.trim()
        if (hostAddress.isBlank()) {
            _uiState.value = _uiState.value.copy(
                portScanSummary = "Select a responsive host before running a port scan.",
                portScanResults = emptyList()
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isPortScanning = true,
                portScanSummary = "Scanning common TCP ports on $hostAddress..."
            )

            val report = withContext(Dispatchers.Default) {
                runPortScanUseCase(hostAddress)
            }

            _uiState.value = _uiState.value.copy(
                isPortScanning = false,
                portScanSummary = report.summary,
                portScanResults = report.scannedPorts.map { result ->
                    "${result.port.toString().padStart(5, ' ')}  ${result.protocol.padEnd(9, ' ')}  ${result.state.name.lowercase()}  ${result.note}"
                }
            )
        }
    }
}
