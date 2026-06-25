package org.fsploit.android.domain.usecase

import java.util.Base64

/** Outcome of probing the Kali chroot for the bits msgrpc needs. */
enum class MsgrpcHelperStatus {
    /** No NetHunter chroot found at the expected path — nothing the app can do. */
    NO_CHROOT,

    /** Chroot present but metasploit isn't installed in it; `msfstart` would fail at runtime. */
    NO_MSF,

    /** Chroot + metasploit present and the `msfstart` helper is in place. */
    READY
}

/**
 * Makes sure the `msfstart` helper exists inside the NetHunter Kali chroot, and reports whether the
 * chroot/metasploit are actually there so the screen can explain why a connection won't come up.
 * The operator runs `msfstart` in the terminal to bring up the interactive `msgrpc` console the app
 * connects to; a kalifs reinstall wipes it, so we re-drop it (and set the exec bit) on demand.
 *
 * All checks are plain path tests from the Android side as root (no chroot needed); the script body
 * is base64'd to dodge shell-quoting/newline pitfalls when piping it through `su`.
 */
class EnsureMsgrpcScriptUseCase(
    private val runShellCommand: RunShellCommandUseCase
) {
    suspend operator fun invoke(): MsgrpcHelperStatus {
        val encoded = Base64.getEncoder().encodeToString(SCRIPT_BODY.toByteArray(Charsets.UTF_8))
        val command = buildString {
            append("D=").append(CHROOT_DIR).append("; ")
            append("F=\"\$D/usr/bin/").append(SCRIPT_NAME).append("\"; ")
            append("if [ ! -d \"\$D\" ]; then echo ").append(MARK_NO_CHROOT).append("; else ")
            append("[ -f \"\$F\" ] || { echo ").append(encoded)
            append(" | base64 -d > \"\$F\" && chmod 755 \"\$F\"; }; ")
            // msfconsole is usually a symlink to an absolute path; from outside the chroot `-e`
            // follows it to the Android root and fails. Accept symlink (-L) and the install dir too.
            append("if [ -e \"\$D/usr/bin/msfconsole\" ] || [ -L \"\$D/usr/bin/msfconsole\" ] || [ -d \"\$D/usr/share/metasploit-framework\" ]; then echo ").append(MARK_READY)
            append("; else echo ").append(MARK_NO_MSF).append("; fi; fi")
        }
        val out = runShellCommand(command = command, asRoot = true, timeoutMs = TIMEOUT_MS).output
        return when {
            out.contains(MARK_NO_CHROOT) -> MsgrpcHelperStatus.NO_CHROOT
            out.contains(MARK_NO_MSF) -> MsgrpcHelperStatus.NO_MSF
            out.contains(MARK_READY) -> MsgrpcHelperStatus.READY
            else -> MsgrpcHelperStatus.NO_CHROOT
        }
    }

    companion object {
        const val SCRIPT_NAME = "msfstart"
        private const val CHROOT_DIR = "/data/local/nhsystem/kalifs"
        private const val MARK_NO_CHROOT = "__FSPLOIT_NO_CHROOT__"
        private const val MARK_NO_MSF = "__FSPLOIT_NO_MSF__"
        private const val MARK_READY = "__FSPLOIT_READY__"
        private const val TIMEOUT_MS = 8_000L
        private val SCRIPT_BODY = """
            #!/bin/bash
            export LANG=C
            msfconsole -q -x "load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=msf Pass=msf SSL=false"
        """.trimIndent() + "\n"
    }
}
