package org.fsploit.android.domain.model

data class PortScanConfig(
    val portSpec: String,
    val connectTimeoutMs: Int,
    val parallelism: Int
)
