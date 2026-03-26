package org.fsploit.android.domain.model

data class NetworkInterfaceInfo(
    val name: String,
    val addresses: List<String>,
    val category: InterfaceCategory,
    val primaryAddress: String? = addresses.firstOrNull(),
    val prefixLength: Int? = null,
    val defaultGatewayAddress: String? = null
)

enum class InterfaceCategory {
    WIFI,
    ETHERNET,
    USB,
    OTHER
}
