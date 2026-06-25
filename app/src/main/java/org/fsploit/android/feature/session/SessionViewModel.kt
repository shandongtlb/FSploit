package org.fsploit.android.feature.session

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.IpUtils
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadLastSweepUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.SaveLastSweepUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase

/**
 * Activity-scoped ViewModel that owns the shared cross-screen [SessionState] (via [SessionStateHolder])
 * and the orchestration that more than one screen depends on: the global refresh, preferred-interface
 * selection, target-host selection, and the host sweep. Per-feature ViewModels read this state
 * reactively through the same holder.
 */
class SessionViewModel(
    private val resourceProvider: ResourceProvider,
    private val holder: SessionStateHolder,
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterfaceUseCase: SavePreferredInterfaceUseCase,
    private val probeShell: ProbeShellUseCase,
    private val runHostSweep: RunHostSweepUseCase,
    private val loadLastSweep: LoadLastSweepUseCase,
    private val saveLastSweep: SaveLastSweepUseCase
) : ViewModel() {

    val uiState: StateFlow<SessionState> = holder.state

    init {
        if (holder.value.permissionSummary.isEmpty()) {
            // Restore the last sweep so the discovered-target list survives process death.
            val (scannedHosts, persistedHosts) = loadLastSweep()
            holder.update {
                it.copy(
                    permissionSummary = resourceProvider.getString(R.string.permission_summary_pending),
                    activeTransportLabel = resourceProvider.getString(R.string.transport_unknown),
                    shellSummary = resourceProvider.getString(R.string.shell_status_pending),
                    rootGateSummary = resourceProvider.getString(R.string.root_gate_pending),
                    scanSummary = resourceProvider.getString(R.string.host_sweep_not_run),
                    responsiveTargetResults = persistedHosts,
                    responsiveHosts = persistedHosts.map { host -> host.hostAddress },
                    scannedHostCount = scannedHosts,
                    selectedHostAddress = persistedHosts.firstOrNull()?.hostAddress.orEmpty()
                )
            }
        }
    }

    fun refresh(permissionSummary: String, permissionsGranted: Boolean) {
        viewModelScope.launch(Dispatchers.Default) {
            val overview = loadNetworkOverview()
            val shellStatus = probeShell()
            val current = holder.value
            val interfaceNames = overview.interfaces.map { it.name }
            val preferredInterfaceName = getPreferredInterface()
                .takeIf { it.isNotBlank() && interfaceNames.contains(it) }
                ?: overview.interfaces.firstOrNull()?.name.orEmpty()
            val resolvedGatewayAddress = overview.interfaces
                .firstOrNull { it.name == preferredInterfaceName }
                ?.defaultGatewayAddress
                .orEmpty()
            val selectedHostAddress = current.selectedHostAddress
                .takeIf { IpUtils.isValidManualHost(it) || current.responsiveHosts.contains(it) }
                ?: current.responsiveHosts.firstOrNull().orEmpty()

            holder.update {
                it.copy(
                    isLoading = false,
                    permissionSummary = permissionSummary,
                    activeTransportLabel = overview.activeTransportLabel,
                    activeInterfaceName = overview.activeInterfaceName,
                    interfaces = overview.interfaces,
                    statusMessage = overview.statusMessage,
                    canContinue = permissionsGranted && overview.interfaces.isNotEmpty() && shellStatus.rootGranted,
                    shellAvailable = shellStatus.shellAvailable,
                    suAvailable = shellStatus.suAvailable,
                    rootGranted = shellStatus.rootGranted,
                    shellSummary = shellStatus.summary,
                    rootGateSummary = if (shellStatus.rootGranted) {
                        resourceProvider.getString(R.string.root_gate_ready)
                    } else {
                        resourceProvider.getString(R.string.root_gate_blocked)
                    },
                    preferredInterfaceName = preferredInterfaceName,
                    resolvedGatewayAddress = resolvedGatewayAddress,
                    selectedHostAddress = selectedHostAddress
                )
            }
        }
    }

    fun savePreferredInterface(interfaceName: String) {
        val trimmed = interfaceName.trim()
        val current = holder.value
        val resolvedGatewayAddress = current.interfaces
            .firstOrNull { it.name == trimmed }
            ?.defaultGatewayAddress
            .orEmpty()
        savePreferredInterfaceUseCase(trimmed)
        holder.update {
            it.copy(
                preferredInterfaceName = trimmed,
                resolvedGatewayAddress = resolvedGatewayAddress
            )
        }
    }

    fun selectHost(hostAddress: String) {
        val trimmed = hostAddress.trim()
        holder.update { it.copy(selectedHostAddress = trimmed) }
    }

    fun runSweep() {
        val current = holder.value
        if (!current.rootGranted) {
            holder.update { it.copy(scanSummary = resourceProvider.getString(R.string.root_gate_blocked)) }
            return
        }
        val interfaceName = current.preferredInterfaceName
        val previousSelectedHostAddress = current.selectedHostAddress.trim()
        viewModelScope.launch {
            holder.update {
                it.copy(
                    isScanning = true,
                    scanSummary = resourceProvider.getString(R.string.host_sweep_running),
                    responsiveTargetResults = emptyList(),
                    responsiveHosts = emptyList()
                )
            }

            val report = withContext(Dispatchers.Default) {
                runHostSweep(interfaceName) { scanned, total ->
                    holder.update {
                        it.copy(
                            scanSummary = resourceProvider.getString(
                                R.string.host_sweep_progress, scanned, total
                            )
                        )
                    }
                }
            }

            val responsiveHosts = report.responsiveHosts.map { it.hostAddress }
            val selectedHostAddress = previousSelectedHostAddress
                .takeIf { IpUtils.isValidManualHost(it) || responsiveHosts.contains(it) }
                ?: responsiveHosts.firstOrNull().orEmpty()

            holder.update {
                it.copy(
                    isScanning = false,
                    scanSummary = report.summary,
                    scannedHostCount = report.scannedHosts,
                    responsiveTargetResults = report.responsiveHosts,
                    responsiveHosts = responsiveHosts,
                    selectedHostAddress = selectedHostAddress
                )
            }
            saveLastSweep(report.scannedHosts, report.responsiveHosts)
        }
    }
}
