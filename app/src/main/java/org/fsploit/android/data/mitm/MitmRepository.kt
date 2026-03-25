package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.ConnectionBlockResult
import org.fsploit.android.domain.model.MitmActionResult
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.ShellStatus
import java.net.Inet4Address
import java.net.InetAddress

class MitmRepository(
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository,
    private val backend: MitmBackend
) {
    fun loadReadiness(shellStatus: ShellStatus): MitmReadiness = backend.loadReadiness(shellStatus)

    fun loadSession(): MitmSession = backend.loadSession()

    fun startSession(request: MitmLaunchRequest): MitmActionResult = backend.startSession(request)

    fun stopSession(): MitmActionResult = backend.stopSession()

    fun blockHost(hostAddress: String): ConnectionBlockResult {
        val host = validateIpv4(hostAddress)
            ?: return ConnectionBlockResult(
                targetHost = hostAddress,
                success = false,
                summary = resourceProvider.getString(R.string.block_invalid_host)
            )

        val result = shellRepository.execute(
            command = buildString {
                append("iptables -C OUTPUT -d ")
                append(host)
                append(" -j DROP 2>/dev/null || iptables -I OUTPUT -d ")
                append(host)
                append(" -j DROP; ")
                append("iptables -C INPUT -s ")
                append(host)
                append(" -j DROP 2>/dev/null || iptables -I INPUT -s ")
                append(host)
                append(" -j DROP")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )

        return ConnectionBlockResult(
            targetHost = host,
            success = result.exitCode == 0 && !result.timedOut,
            summary = if (result.exitCode == 0 && !result.timedOut) {
                resourceProvider.getString(R.string.block_applied, host)
            } else {
                resourceProvider.getString(R.string.block_failed, host, result.summary)
            }
        )
    }

    fun unblockHost(hostAddress: String): ConnectionBlockResult {
        val host = validateIpv4(hostAddress)
            ?: return ConnectionBlockResult(
                targetHost = hostAddress,
                success = false,
                summary = resourceProvider.getString(R.string.block_invalid_host)
            )

        val result = shellRepository.execute(
            command = buildString {
                append("while iptables -D OUTPUT -d ")
                append(host)
                append(" -j DROP 2>/dev/null; do :; done; ")
                append("while iptables -D INPUT -s ")
                append(host)
                append(" -j DROP 2>/dev/null; do :; done")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )

        return ConnectionBlockResult(
            targetHost = host,
            success = result.exitCode == 0 && !result.timedOut,
            summary = if (result.exitCode == 0 && !result.timedOut) {
                resourceProvider.getString(R.string.block_removed, host)
            } else {
                resourceProvider.getString(R.string.block_remove_failed, host, result.summary)
            }
        )
    }

    private fun validateIpv4(hostAddress: String): String? {
        return try {
            val address = InetAddress.getByName(hostAddress.trim())
            if (address is Inet4Address) address.hostAddress else null
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        private const val FIREWALL_TIMEOUT_MS = 4000L
    }
}
