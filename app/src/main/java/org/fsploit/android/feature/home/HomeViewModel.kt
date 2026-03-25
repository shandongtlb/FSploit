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
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase

class HomeViewModel(
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterfaceUseCase: SavePreferredInterfaceUseCase,
    private val probeShell: ProbeShellUseCase,
    private val runHostSweep: RunHostSweepUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    fun refresh(permissionSummary: String, permissionsGranted: Boolean) {
        viewModelScope.launch(Dispatchers.Default) {
            val overview = loadNetworkOverview()
            val shellStatus = probeShell()
            val preferredInterfaceName = getPreferredInterface()
                .takeIf { it.isNotBlank() }
                ?: overview.interfaces.firstOrNull()?.name.orEmpty()

            _uiState.value = HomeUiState(
                isLoading = false,
                permissionSummary = permissionSummary,
                activeTransportLabel = overview.activeTransportLabel,
                interfaces = overview.interfaces,
                statusMessage = overview.statusMessage,
                canContinue = permissionsGranted && overview.interfaces.isNotEmpty(),
                shellSummary = shellStatus.summary,
                preferredInterfaceName = preferredInterfaceName,
                scanSummary = _uiState.value.scanSummary,
                scanResults = _uiState.value.scanResults,
                isScanning = false
            )
        }
    }

    fun savePreferredInterface(interfaceName: String) {
        val trimmed = interfaceName.trim()
        savePreferredInterfaceUseCase(trimmed)
        _uiState.value = _uiState.value.copy(preferredInterfaceName = trimmed)
    }

    fun runSweep() {
        val interfaceName = _uiState.value.preferredInterfaceName
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isScanning = true,
                scanSummary = "Running host sweep..."
            )

            val report = withContext(Dispatchers.Default) {
                runHostSweep(interfaceName)
            }

            _uiState.value = _uiState.value.copy(
                isScanning = false,
                scanSummary = report.summary,
                scanResults = report.responsiveHosts.map { "${it.hostAddress}  ${it.finding}" }
            )
        }
    }
}
