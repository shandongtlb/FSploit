package org.fsploit.android.domain.model

/** Outcome of a one-shot MSF RPC action (stop a session, stop a job). */
data class MsfActionResult(
    val success: Boolean,
    val message: String
)
