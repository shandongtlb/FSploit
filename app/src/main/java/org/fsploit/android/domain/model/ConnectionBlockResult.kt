package org.fsploit.android.domain.model

data class ConnectionBlockResult(
    val targetHost: String,
    val success: Boolean,
    val summary: String
)
