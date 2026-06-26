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

    /**
     * Authoritative current connection-block target, reconciled against the live process / iptables
     * state (clears a stale record). Empty string when nothing is blocked. Lets the UI rebuild block
     * state after a restart instead of trusting only in-memory flags.
     */
    fun loadActiveBlock(): String

    /**
     * Tear down every active artifact this backend owns — the MITM session AND any standalone
     * connection block — and restore the network (ip_forward, iptables redirect/drop rules) from
     * the stored records. Backs the foreground-service "stop all / restore network" action so a
     * left-on MITM never silently keeps mangling traffic.
     */
    fun stopAll(): MitmActionResult
}
