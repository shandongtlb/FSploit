package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.ConnectionBlockResult
import org.fsploit.android.domain.model.ConnectionBlockMode
import org.fsploit.android.domain.model.MitmActionResult
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.ShellStatus
import java.net.Inet4Address
import java.net.InetAddress

class MitmRepository(
    private val resourceProvider: ResourceProvider,
    private val backend: MitmBackend
) {
    fun loadReadiness(shellStatus: ShellStatus): MitmReadiness = backend.loadReadiness(shellStatus)

    fun loadSession(): MitmSession = backend.loadSession()

    fun startSession(request: MitmLaunchRequest): MitmActionResult = backend.startSession(request)

    fun stopSession(): MitmActionResult = backend.stopSession()

    fun blockHost(
        hostAddress: String,
        interfaceName: String,
        gatewayAddress: String,
        mode: ConnectionBlockMode
    ): ConnectionBlockResult {
        val host = validateIpv4(hostAddress)
            ?: return ConnectionBlockResult(
                targetHost = hostAddress,
                success = false,
                summary = resourceProvider.getString(R.string.block_invalid_host)
            )
        return backend.blockHost(host, interfaceName, gatewayAddress, mode)
    }

    fun unblockHost(hostAddress: String): ConnectionBlockResult {
        val host = validateIpv4(hostAddress)
            ?: return ConnectionBlockResult(
                targetHost = hostAddress,
                success = false,
                summary = resourceProvider.getString(R.string.block_invalid_host)
            )
        return backend.unblockHost(host)
    }

    private fun validateIpv4(hostAddress: String): String? {
        return try {
            val address = InetAddress.getByName(hostAddress.trim())
            if (address is Inet4Address) address.hostAddress else null
        } catch (_: Exception) {
            null
        }
    }
}
