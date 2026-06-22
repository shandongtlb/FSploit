package org.fsploit.android.data.mitm

import org.fsploit.android.domain.model.MitmActionResult
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.ShellStatus
import org.fsploit.android.domain.model.ConnectionBlockResult
import org.fsploit.android.domain.model.ConnectionBlockMode

interface MitmBackend {
    fun loadReadiness(shellStatus: ShellStatus): MitmReadiness
    fun loadSession(): MitmSession
    fun startSession(request: MitmLaunchRequest): MitmActionResult
    fun stopSession(): MitmActionResult
    fun blockHost(
        targetHost: String,
        interfaceName: String,
        gatewayAddress: String,
        mode: ConnectionBlockMode
    ): ConnectionBlockResult
    fun unblockHost(hostAddress: String): ConnectionBlockResult
}
