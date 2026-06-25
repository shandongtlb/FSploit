package org.fsploit.android.domain.usecase

import java.util.Base64

/**
 * Makes sure the `msfstart` helper exists inside the NetHunter Kali chroot. The operator runs it in
 * the terminal to bring up the interactive `msgrpc` console the app connects to; a kalifs reinstall
 * wipes it, so we re-drop it (and set the exec bit) whenever the MSF screen opens.
 *
 * Written from the Android side straight to the chroot's host path as root. The body is base64'd to
 * dodge all shell-quoting/newline pitfalls when piping it through `su`.
 */
class EnsureMsgrpcScriptUseCase(
    private val runShellCommand: RunShellCommandUseCase
) {
    /** Returns true if the script was newly installed this call (already-present is a no-op). */
    suspend operator fun invoke(): Boolean {
        val encoded = Base64.getEncoder().encodeToString(SCRIPT_BODY.toByteArray(Charsets.UTF_8))
        val command = buildString {
            append("D=").append(BIN_DIR).append("; F=\"\$D/").append(SCRIPT_NAME).append("\"; ")
            append("if [ -d \"\$D\" ] && [ ! -f \"\$F\" ]; then ")
            append("echo ").append(encoded).append(" | base64 -d > \"\$F\" && chmod 755 \"\$F\" && echo ")
            append(INSTALLED_MARKER)
            append("; fi")
        }
        val result = runShellCommand(command = command, asRoot = true, timeoutMs = TIMEOUT_MS)
        return result.output.contains(INSTALLED_MARKER)
    }

    companion object {
        const val SCRIPT_NAME = "msfstart"
        private const val BIN_DIR = "/data/local/nhsystem/kalifs/usr/bin"
        private const val INSTALLED_MARKER = "__FSPLOIT_MSFSTART_INSTALLED__"
        private const val TIMEOUT_MS = 8_000L
        private val SCRIPT_BODY = """
            #!/bin/bash
            export LANG=C
            msfconsole -q -x "load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=msf SSL=false"
        """.trimIndent() + "\n"
    }
}
