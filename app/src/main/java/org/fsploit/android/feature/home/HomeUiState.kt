package org.fsploit.android.feature.home

import org.fsploit.android.domain.model.NetworkInterfaceInfo
import org.fsploit.android.domain.model.ConnectionBlockMode
import org.fsploit.android.domain.model.HostScanResult
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.MitmToolchainConfig
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.feature.target.PortResultFilter

data class HomeUiState(
    val isLoading: Boolean = true,
    val permissionSummary: String = "",
    val activeTransportLabel: String = "",
    val activeInterfaceName: String = "",
    val interfaces: List<NetworkInterfaceInfo> = emptyList(),
    val statusMessage: String = "",
    val canContinue: Boolean = false,
    val shellAvailable: Boolean = false,
    val suAvailable: Boolean = false,
    val rootGranted: Boolean = false,
    val shellSummary: String = "",
    val rootGateSummary: String = "",
    val preferredInterfaceName: String = "",
    val scanSummary: String = "",
    val scanResults: List<String> = emptyList(),
    val responsiveTargetResults: List<HostScanResult> = emptyList(),
    val responsiveHosts: List<String> = emptyList(),
    val selectedHostAddress: String = "",
    val isScanning: Boolean = false,
    val portSpec: String = "",
    val connectTimeoutMs: String = "",
    val parallelism: String = "",
    val mitmSummary: String = "",
    val iptablesAvailable: Boolean = false,
    val tcpdumpAvailable: Boolean = false,
    val bettercapAvailable: Boolean = false,
    val mitmdumpAvailable: Boolean = false,
    val certificateStoreAccessible: Boolean = false,
    val selectedMitmMode: MitmMode = MitmMode.SNIFFER,
    val resolvedGatewayAddress: String = "",
    val mitmGatewayInput: String = "",
    val mitmPrimaryInput: String = "",
    val mitmSecondaryInput: String = "",
    val mitmPayloadInput: String = "",
    val mitmSession: MitmSession = MitmSession(),
    val mitmSessionSummary: String = "",
    val isStartingMitmSession: Boolean = false,
    val mitmDiagnosticsSummary: String = "",
    val mitmDiagnosticsOutput: String = "",
    val isRunningMitmDiagnostics: Boolean = false,
    val mitmToolchainConfig: MitmToolchainConfig = MitmToolchainConfig(),
    val mitmSettingsSummary: String = "",
    val isSavingMitmToolchainConfig: Boolean = false,
    val portScanSummary: String = "",
    val scannedPortResults: List<PortScanResult> = emptyList(),
    val portScanResults: List<String> = emptyList(),
    val selectedPortResultFilter: PortResultFilter = PortResultFilter.ALL,
    val isPortScanning: Boolean = false,
    val blockedHostAddress: String = "",
    val selectedConnectionBlockMode: ConnectionBlockMode = ConnectionBlockMode.NORMAL,
    val recommendedConnectionBlockMode: ConnectionBlockMode = ConnectionBlockMode.NORMAL,
    val isConnectionBlockModeOverridden: Boolean = false,
    val connectionBlockModeSummary: String = "",
    val connectionBlockSummary: String = "",
    val isBlockingConnection: Boolean = false,
    val selectedShellTaskLabel: String = "",
    val selectedShellTaskDescription: String = "",
    val shellCommandInput: String = "",
    val shellRunAsRoot: Boolean = false,
    val shellExecutionSummary: String = "",
    val shellExecutionOutput: String = "",
    val isExecutingShell: Boolean = false
)
