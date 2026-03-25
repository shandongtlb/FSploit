package org.fsploit.android.domain.model

data class ShellStatus(
    val shellAvailable: Boolean,
    val suAvailable: Boolean,
    val rootGranted: Boolean,
    val summary: String
)
