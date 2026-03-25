package org.fsploit.android.domain.model

data class NetworkInterfaceInfo(
    val name: String,
    val addresses: List<String>,
    val category: InterfaceCategory
)

enum class InterfaceCategory {
    WIFI,
    ETHERNET,
    USB,
    OTHER
}
