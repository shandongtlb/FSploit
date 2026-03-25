package org.fsploit.android.feature.home

import org.fsploit.android.domain.model.NetworkInterfaceInfo

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
    val responsiveHosts: List<String> = emptyList(),
    val selectedHostAddress: String = "",
    val isScanning: Boolean = false,
    val portSpec: String = "",
    val connectTimeoutMs: String = "",
    val parallelism: String = "",
    val portScanSummary: String = "",
    val portScanResults: List<String> = emptyList(),
    val isPortScanning: Boolean = false,
    val shellCommandInput: String = "",
    val shellRunAsRoot: Boolean = false,
    val shellExecutionSummary: String = "",
    val shellExecutionOutput: String = "",
    val isExecutingShell: Boolean = false
)
