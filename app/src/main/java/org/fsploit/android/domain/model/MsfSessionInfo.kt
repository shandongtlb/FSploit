package org.fsploit.android.domain.model

data class MsfSessionInfo(
    val id: String,
    val type: String,
    val tunnelPeer: String,
    val targetHost: String,
    val viaExploit: String,
    val description: String
)
