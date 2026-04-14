package org.fsploit.android.domain.model

data class MsfRpcConfig(
    val host: String = "127.0.0.1",
    val port: Int = 55552,
    val username: String = "msf",
    val password: String = "msf",
    val useSsl: Boolean = false,
    val launchCommand: String = ""
)
