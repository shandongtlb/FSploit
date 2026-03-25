package org.fsploit.android.feature.home

import org.fsploit.android.domain.model.NetworkInterfaceInfo

data class HomeUiState(
    val isLoading: Boolean = true,
    val selectedSection: HomeSection = HomeSection.OVERVIEW,
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
    val portScanSummary: String = "",
    val portScanResults: List<String> = emptyList(),
    val isPortScanning: Boolean = false
)
