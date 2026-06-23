package org.fsploit.android.domain.model

/**
 * One captured item parsed out of a MITM artifact (bettercap credential log or
 * mitmdump cookie jsonl). Structured fields are best-effort — [raw] always holds
 * the original line so nothing is lost when parsing can't extract user/pass.
 */
data class SniffedCredential(
    val timestamp: String = "",
    val protocol: String = "",
    val source: String = "",
    val username: String = "",
    val password: String = "",
    val raw: String = ""
)
