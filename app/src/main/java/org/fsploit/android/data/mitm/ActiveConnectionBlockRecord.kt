package org.fsploit.android.data.mitm

import org.fsploit.android.domain.model.ConnectionBlockMode

data class ActiveConnectionBlockRecord(
    val targetHost: String,
    val interfaceName: String,
    val mode: ConnectionBlockMode,
    val pid: Long?,
    val logPath: String,
    val startedAtEpochMs: Long
)
