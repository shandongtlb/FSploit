package org.fsploit.android.domain.model

data class MitmSession(
    val active: Boolean = false,
    val mode: MitmMode? = null,
    val targetHost: String = "",
    val interfaceName: String = "",
    val summary: String = "",
    val logPath: String = "",
    val artifactPath: String = "",
    val startedAtEpochMs: Long = 0L
)
