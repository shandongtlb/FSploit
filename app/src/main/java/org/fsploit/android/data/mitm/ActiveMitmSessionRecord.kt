package org.fsploit.android.data.mitm

import org.fsploit.android.domain.model.MitmSession

data class ActiveMitmSessionRecord(
    val session: MitmSession,
    val pids: List<Long>,
    val redirectPort: Int,
    val forwardingEnabled: Boolean,
    val forwardDropTargetHost: String = ""
)
