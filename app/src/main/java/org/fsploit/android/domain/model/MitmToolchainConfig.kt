package org.fsploit.android.domain.model

data class MitmToolchainConfig(
    val arpspoofPath: String = "arpspoof",
    val tcpdumpPath: String = "tcpdump",
    val ettercapPath: String = "ettercap",
    val mitmdumpPath: String = "mitmdump",
    val httpRedirectPort: Int = 18080
)
