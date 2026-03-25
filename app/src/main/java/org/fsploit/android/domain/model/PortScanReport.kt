package org.fsploit.android.domain.model

data class PortScanReport(
    val hostAddress: String,
    val requestedPorts: List<Int>,
    val scannedPorts: List<PortScanResult>,
    val summary: String
)
