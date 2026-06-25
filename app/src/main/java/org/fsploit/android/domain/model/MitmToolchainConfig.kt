package org.fsploit.android.domain.model

data class MitmToolchainConfig(
    val bettercapPath: String = "bettercap",
    val tcpdumpPath: String = "tcpdump",
    val mitmdumpPath: String = "mitmdump",
    val nmapPath: String = "nmap",
    val httpRedirectPort: Int = 18080
)
