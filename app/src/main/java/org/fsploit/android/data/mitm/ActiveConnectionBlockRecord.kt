package org.fsploit.android.data.mitm

data class ActiveConnectionBlockRecord(
    val targetHost: String,
    val interfaceName: String,
    val pid: Long,
    val logPath: String,
    val startedAtEpochMs: Long
)
