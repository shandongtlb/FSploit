package org.fsploit.android.domain.model

data class HostScanResult(
    val hostAddress: String,
    val finding: String,
    val macAddress: String? = null,
    val vendor: String? = null,
    val osInfo: String? = null
)
