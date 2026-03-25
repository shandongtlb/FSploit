package org.fsploit.android.feature.home

import org.fsploit.android.domain.model.NetworkInterfaceInfo
import org.fsploit.android.domain.model.HostScanResult
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.feature.target.PortResultFilter

data class HomeUiState(
    val isLoading: Boolean = true,
    val permissionSummary: String = "",
    val activeTransportLabel: String = "",
    val interfaces: List<NetworkInterfaceInfo> = emptyList(),
    val statusMessage: String = "",
    val canContinue: Boolean = false,
    val shellSummary: String = "",
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
    val portScanSummary: String = "",
    val scannedPortResults: List<PortScanResult> = emptyList(),
    val portScanResults: List<String> = emptyList(),
    val selectedPortResultFilter: PortResultFilter = PortResultFilter.ALL,
    val isPortScanning: Boolean = false,
    val selectedShellTaskLabel: String = "",
    val selectedShellTaskDescription: String = "",
    val shellCommandInput: String = "",
    val shellRunAsRoot: Boolean = false,
    val shellExecutionSummary: String = "",
    val shellExecutionOutput: String = "",
    val isExecutingShell: Boolean = false
)
