package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.CredentialLogParser
import org.fsploit.android.domain.model.MitmLootSnapshot
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmSession

/**
 * Reads the active MITM session's loot artifact and parses it. The artifact is written by a
 * root-launched bettercap/mitmdump process, so it is read back through a root shell `cat`.
 * SNIFFER mode produces a binary pcap which is reported (with its path) rather than parsed.
 */
class ReadMitmLootUseCase(
    private val runShellCommand: RunShellCommandUseCase,
    private val parser: CredentialLogParser
) {
    suspend operator fun invoke(session: MitmSession): MitmLootSnapshot {
        val path = session.artifactPath.trim()
        if (path.isBlank()) {
            return MitmLootSnapshot(artifactPath = "")
        }
        if (session.mode == MitmMode.SNIFFER) {
            return MitmLootSnapshot(artifactPath = path, available = true, binaryCapture = true)
        }

        val result = runShellCommand(
            command = "cat ${singleQuote(path)}",
            asRoot = true,
            timeoutMs = LOOT_READ_TIMEOUT_MS
        )
        if (result.timedOut || (result.exitCode != null && result.exitCode != 0)) {
            return MitmLootSnapshot(artifactPath = path, available = false)
        }

        val content = result.output
        val entries = when (session.mode) {
            MitmMode.SESSION_HIJACK -> parser.parseCookiesJsonl(content)
            else -> parser.parseCredentialsLog(content)
        }
        return MitmLootSnapshot(
            artifactPath = path,
            available = true,
            entries = entries,
            rawLineCount = content.lineSequence().count { it.isNotBlank() }
        )
    }

    private fun singleQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

    companion object {
        private const val LOOT_READ_TIMEOUT_MS = 5000L
    }
}
