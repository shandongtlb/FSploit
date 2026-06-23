package org.fsploit.android.domain.model

/** Result of reading from / writing to an interactive MSF session console. */
data class MsfConsoleResult(
    val success: Boolean,
    val data: String,
    val message: String
)
