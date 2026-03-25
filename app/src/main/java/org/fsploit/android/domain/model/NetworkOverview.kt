package org.fsploit.android.domain.model

data class NetworkOverview(
    val activeTransportLabel: String,
    val interfaces: List<NetworkInterfaceInfo>,
    val statusMessage: String
)
