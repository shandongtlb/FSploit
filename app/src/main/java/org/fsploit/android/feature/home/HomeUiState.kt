package org.fsploit.android.feature.home

import org.fsploit.android.domain.model.NetworkInterfaceInfo

data class HomeUiState(
    val isLoading: Boolean = true,
    val permissionSummary: String = "Checking permissions",
    val activeTransportLabel: String = "Unknown",
    val interfaces: List<NetworkInterfaceInfo> = emptyList(),
    val statusMessage: String = "",
    val canContinue: Boolean = false
)
