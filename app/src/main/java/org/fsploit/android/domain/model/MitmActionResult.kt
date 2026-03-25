package org.fsploit.android.domain.model

data class MitmActionResult(
    val success: Boolean,
    val summary: String,
    val session: MitmSession = MitmSession()
)
