package org.fsploit.android.domain.model

data class ShellCommandResult(
    val command: String,
    val output: String,
    val exitCode: Int?,
    val timedOut: Boolean,
    val executedAsRoot: Boolean,
    val summary: String
)
