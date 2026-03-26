package org.fsploit.android.domain.model

data class MitmLaunchRequest(
    val mode: MitmMode,
    val targetHost: String,
    val interfaceName: String,
    val gatewayAddress: String = "",
    val primaryValue: String = "",
    val secondaryValue: String = "",
    val payloadValue: String = ""
)
