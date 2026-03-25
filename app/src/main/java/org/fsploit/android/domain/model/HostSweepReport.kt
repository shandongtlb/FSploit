package org.fsploit.android.domain.model

data class HostSweepReport(
    val interfaceName: String,
    val subnetLabel: String,
    val scannedHosts: Int,
    val responsiveHosts: List<HostScanResult>,
    val summary: String
)
