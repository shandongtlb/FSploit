package org.fsploit.android.domain.model

data class MitmToolchainConfig(
    val bettercapPath: String = "bettercap",
    val tcpdumpPath: String = "tcpdump",
    val mitmdumpPath: String = "mitmdump",
    val httpRedirectPort: Int = 18080
)
