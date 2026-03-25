package org.fsploit.android.domain.model

data class PortScanReport(
    val hostAddress: String,
    val scannedPorts: List<PortScanResult>,
    val summary: String
)
