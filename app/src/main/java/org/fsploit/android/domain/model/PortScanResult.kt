package org.fsploit.android.domain.model

data class PortScanResult(
    val port: Int,
    val protocol: String,
    val state: PortState,
    val note: String
)

enum class PortState {
    OPEN,
    CLOSED,
    FILTERED
}
