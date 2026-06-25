package org.fsploit.android.domain.model

data class PortScanResult(
    val port: Int,
    val protocol: String,
    val state: PortState,
    val note: String,
    val service: String? = null,
    val product: String? = null,
    val version: String? = null
)

enum class PortState {
    OPEN,
    CLOSED,
    FILTERED
}
