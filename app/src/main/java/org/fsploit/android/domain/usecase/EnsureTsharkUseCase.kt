package org.fsploit.android.domain.usecase

/** Whether the NetHunter chroot has the tshark the pcap viewer needs for dissection + TLS decryption. */
enum class TsharkStatus {
    /** No NetHunter chroot at the expected path. */
    NO_CHROOT,

    /** Chroot present but tshark isn't installed (`apt install tshark`). */
    NO_TSHARK,

    /** Chroot + tshark present. */
    READY
}

/**
 * Probes the Kali chroot for `tshark`. tshark needs heavy shared libs so it can only run *inside* the
 * chroot; this just reports availability so the viewer can decide between the tshark engine and the
 * built-in Kotlin parser. Like the msgrpc probe, the binary is usually a symlink — from outside the
 * chroot `-e` follows the absolute target against the Android root and fails, so `-L` is accepted too.
 */
class EnsureTsharkUseCase(
    private val runShellCommand: RunShellCommandUseCase
) {
    suspend operator fun invoke(): TsharkStatus {
        val command = buildString {
            append("D=").append(CHROOT_DIR).append("; ")
            append("if [ ! -d \"\$D\" ]; then echo ").append(MARK_NO_CHROOT).append("; ")
            append("elif [ -e \"\$D/usr/bin/tshark\" ] || [ -L \"\$D/usr/bin/tshark\" ]; then echo ").append(MARK_READY).append("; ")
            append("else echo ").append(MARK_NO_TSHARK).append("; fi")
        }
        val out = runShellCommand(command = command, asRoot = true, timeoutMs = TIMEOUT_MS).output
        return when {
            out.contains(MARK_NO_CHROOT) -> TsharkStatus.NO_CHROOT
            out.contains(MARK_NO_TSHARK) -> TsharkStatus.NO_TSHARK
            out.contains(MARK_READY) -> TsharkStatus.READY
            else -> TsharkStatus.NO_CHROOT
        }
    }

    companion object {
        const val CHROOT_DIR = "/data/local/nhsystem/kalifs"
        private const val MARK_NO_CHROOT = "__FSPLOIT_TS_NO_CHROOT__"
        private const val MARK_NO_TSHARK = "__FSPLOIT_TS_NO_TSHARK__"
        private const val MARK_READY = "__FSPLOIT_TS_READY__"
        private const val TIMEOUT_MS = 6_000L
    }
}
