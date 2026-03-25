package org.fsploit.android.feature.home

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
import org.fsploit.android.core.ShellTaskPreset
import org.fsploit.android.domain.model.PortScanConfig
import org.fsploit.android.domain.model.PortState
import org.fsploit.android.domain.usecase.BlockHostUseCase
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadMitmReadinessUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SavePortScanConfigUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.UnblockHostUseCase
import org.fsploit.android.feature.target.PortResultFilter

class HomeViewModel(
    private val resourceProvider: ResourceProvider,
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterfaceUseCase: SavePreferredInterfaceUseCase,
    private val loadPortScanConfig: LoadPortScanConfigUseCase,
    private val savePortScanConfig: SavePortScanConfigUseCase,
    private val probeShell: ProbeShellUseCase,
    private val loadMitmReadinessUseCase: LoadMitmReadinessUseCase,
    private val runHostSweep: RunHostSweepUseCase,
    private val runPortScanUseCase: RunPortScanUseCase,
    private val runShellCommandUseCase: RunShellCommandUseCase,
    private val blockHostUseCase: BlockHostUseCase,
    private val unblockHostUseCase: UnblockHostUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        HomeUiState(
            permissionSummary = resourceProvider.getString(R.string.permission_summary_pending),
            activeTransportLabel = resourceProvider.getString(R.string.transport_unknown),
            shellSummary = resourceProvider.getString(R.string.shell_status_pending),
            scanSummary = resourceProvider.getString(R.string.host_sweep_not_run),
            portSpec = loadPortScanConfig().portSpec,
            connectTimeoutMs = loadPortScanConfig().connectTimeoutMs.toString(),
            parallelism = loadPortScanConfig().parallelism.toString(),
            rootGateSummary = resourceProvider.getString(R.string.root_gate_pending),
            mitmSummary = resourceProvider.getString(R.string.mitm_pending),
            portScanSummary = resourceProvider.getString(R.string.port_scan_not_run),
            connectionBlockSummary = resourceProvider.getString(R.string.block_idle),
            selectedShellTaskLabel = resourceProvider.getString(R.string.shell_task_custom),
            selectedShellTaskDescription = resourceProvider.getString(R.string.shell_task_custom_desc),
            shellExecutionSummary = resourceProvider.getString(R.string.shell_command_idle)
        )
    )
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    fun refresh(permissionSummary: String, permissionsGranted: Boolean) {
        viewModelScope.launch(Dispatchers.Default) {
            val overview = loadNetworkOverview()
            val shellStatus = probeShell()
            val mitmReadiness = loadMitmReadinessUseCase(shellStatus)
            val currentState = _uiState.value
            val preferredInterfaceName = getPreferredInterface()
                .takeIf { it.isNotBlank() }
                ?: overview.interfaces.firstOrNull()?.name.orEmpty()
            val selectedHostAddress = currentState.selectedHostAddress
                .takeIf { currentState.responsiveHosts.contains(it) }
                ?: currentState.responsiveHosts.firstOrNull().orEmpty()
            val storedPortScanConfig = loadPortScanConfig()

            _uiState.value = currentState.copy(
                isLoading = false,
                permissionSummary = permissionSummary,
                activeTransportLabel = overview.activeTransportLabel,
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
                responsiveTargetResults = currentState.responsiveTargetResults,
                responsiveHosts = currentState.responsiveHosts,
                selectedHostAddress = selectedHostAddress,
                isScanning = false,
                portSpec = currentState.portSpec.ifBlank { storedPortScanConfig.portSpec },
                connectTimeoutMs = currentState.connectTimeoutMs.ifBlank {
                    storedPortScanConfig.connectTimeoutMs.toString()
                },
                parallelism = currentState.parallelism.ifBlank {
                    storedPortScanConfig.parallelism.toString()
                },
                mitmSummary = mitmReadiness.summary,
                iptablesAvailable = mitmReadiness.iptablesAvailable,
                tcpdumpAvailable = mitmReadiness.tcpdumpAvailable,
                certificateStoreAccessible = mitmReadiness.certificateStoreAccessible,
                scannedPortResults = currentState.scannedPortResults,
                selectedPortResultFilter = currentState.selectedPortResultFilter,
                isPortScanning = false,
                blockedHostAddress = currentState.blockedHostAddress,
                connectionBlockSummary = currentState.connectionBlockSummary.ifBlank {
                    resourceProvider.getString(R.string.block_idle)
                },
                isBlockingConnection = false,
                selectedShellTaskLabel = currentState.selectedShellTaskLabel,
                selectedShellTaskDescription = currentState.selectedShellTaskDescription,
                isExecutingShell = false
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
            selectedHostAddress = trimmed,
            portScanSummary = if (trimmed.isBlank()) {
                resourceProvider.getString(R.string.port_scan_no_selected_host)
            } else {
                resourceProvider.getString(R.string.port_scan_ready, trimmed)
            }
        )
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

    fun updateShellCommand(command: String) {
        _uiState.value = _uiState.value.copy(
            shellCommandInput = command,
            selectedShellTaskLabel = resourceProvider.getString(R.string.shell_task_custom),
            selectedShellTaskDescription = resourceProvider.getString(R.string.shell_task_custom_desc)
        )
    }

    fun updateShellRunAsRoot(asRoot: Boolean) {
        _uiState.value = _uiState.value.copy(shellRunAsRoot = asRoot)
    }

    fun applyShellPreset(command: String) {
        _uiState.value = _uiState.value.copy(shellCommandInput = command)
    }

    fun applyShellTaskPreset(task: ShellTaskPreset) {
        _uiState.value = _uiState.value.copy(
            selectedShellTaskLabel = resourceProvider.getString(task.titleRes),
            selectedShellTaskDescription = resourceProvider.getString(task.descriptionRes),
            shellCommandInput = task.command,
            shellRunAsRoot = task.runAsRoot
        )
    }

    fun selectPortResultFilter(filter: PortResultFilter) {
        _uiState.value = _uiState.value.copy(selectedPortResultFilter = filter)
    }

    fun runSweep() {
        if (!ensureRootReady()) {
            return
        }
        val interfaceName = _uiState.value.preferredInterfaceName
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isScanning = true,
                scanSummary = resourceProvider.getString(R.string.host_sweep_running),
                responsiveTargetResults = emptyList(),
                responsiveHosts = emptyList(),
                selectedHostAddress = "",
                portScanSummary = resourceProvider.getString(R.string.port_scan_not_run),
                scannedPortResults = emptyList(),
                portScanResults = emptyList(),
                selectedPortResultFilter = PortResultFilter.ALL,
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
                responsiveTargetResults = report.responsiveHosts,
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
        if (!ensureRootReady()) {
            return
        }
        val hostAddress = _uiState.value.selectedHostAddress.trim()
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

    fun runShellCommand() {
        val state = _uiState.value
        if (!state.rootGranted && state.shellRunAsRoot) {
            _uiState.value = state.copy(
                shellExecutionSummary = resourceProvider.getString(R.string.root_gate_blocked),
                shellExecutionOutput = ""
            )
            return
        }
        val command = state.shellCommandInput.trim()
        if (command.isEmpty()) {
            _uiState.value = state.copy(
                shellExecutionSummary = resourceProvider.getString(R.string.shell_command_empty),
                shellExecutionOutput = ""
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = state.copy(
                isExecutingShell = true,
                shellExecutionSummary = resourceProvider.getString(R.string.shell_command_running)
            )

            val result = withContext(Dispatchers.Default) {
                runShellCommandUseCase(
                    command = command,
                    asRoot = state.shellRunAsRoot,
                    timeoutMs = SHELL_COMMAND_TIMEOUT_MS
                )
            }

            _uiState.value = _uiState.value.copy(
                isExecutingShell = false,
                shellExecutionSummary = result.summary,
                shellExecutionOutput = result.output.ifBlank {
                    resourceProvider.getString(R.string.shell_command_no_output)
                }
            )
        }
    }

    fun blockSelectedHost() {
        performConnectionBlock(block = true)
    }

    fun unblockSelectedHost() {
        performConnectionBlock(block = false)
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

    private fun ensureRootReady(): Boolean {
        if (_uiState.value.rootGranted) {
            return true
        }

        _uiState.value = _uiState.value.copy(
            connectionBlockSummary = resourceProvider.getString(R.string.root_gate_blocked),
            portScanSummary = resourceProvider.getString(R.string.root_gate_blocked),
            shellExecutionSummary = resourceProvider.getString(R.string.root_gate_blocked)
        )
        return false
    }

    private fun performConnectionBlock(block: Boolean) {
        if (!ensureRootReady()) {
            return
        }

        val hostAddress = _uiState.value.selectedHostAddress.trim()
        if (hostAddress.isBlank()) {
            _uiState.value = _uiState.value.copy(
                connectionBlockSummary = resourceProvider.getString(R.string.block_select_target_first)
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isBlockingConnection = true,
                connectionBlockSummary = if (block) {
                    resourceProvider.getString(R.string.block_running, hostAddress)
                } else {
                    resourceProvider.getString(R.string.unblock_running, hostAddress)
                }
            )

            val result = withContext(Dispatchers.Default) {
                if (block) blockHostUseCase(hostAddress) else unblockHostUseCase(hostAddress)
            }

            _uiState.value = _uiState.value.copy(
                isBlockingConnection = false,
                blockedHostAddress = if (block && result.success) {
                    result.targetHost
                } else if (!block && result.success && _uiState.value.blockedHostAddress == result.targetHost) {
                    ""
                } else {
                    _uiState.value.blockedHostAddress
                },
                connectionBlockSummary = result.summary
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

    companion object {
        private const val SHELL_COMMAND_TIMEOUT_MS = 5000L
    }
}
