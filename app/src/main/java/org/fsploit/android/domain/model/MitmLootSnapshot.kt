package org.fsploit.android.domain.model

/** Result of reading the loot artifact of the active MITM session at one point in time. */
data class MitmLootSnapshot(
    val artifactPath: String = "",
    val available: Boolean = false,
    val binaryCapture: Boolean = false,
    val entries: List<SniffedCredential> = emptyList(),
    val rawLineCount: Int = 0
)
