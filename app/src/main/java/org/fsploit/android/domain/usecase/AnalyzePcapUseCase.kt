package org.fsploit.android.domain.usecase

import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.R
import org.fsploit.android.data.pcap.PcapParser
import org.fsploit.android.domain.model.PcapAnalysis
import org.fsploit.android.domain.model.PcapEngine
import org.fsploit.android.domain.model.PcapHttpMessage
import java.util.Base64

/**
 * Analyzes a session's pcap. The file is written by a root-launched tcpdump into the app's private
 * dir, so it is read back through a root shell as base64 (not `cat` — [org.fsploit.android.domain
 * .model.ShellCommandResult] carries text and would mangle raw bytes), then decoded and parsed.
 *
 * Two engines, with the Kotlin one always computed as the baseline/fallback:
 *  - **Kotlin** ([PcapParser]): no chroot/tools, flows + cleartext HTTP + packet list, never decrypts.
 *  - **tshark** (inside the NetHunter chroot): when present, lifts HTTP — decrypted with the imported
 *    keylog if one was provided. tshark needs heavy libs so it only runs inside the chroot, and the
 *    pcap/keylog live outside it, so they are copied into `<kalifs>/tmp` first. Any failure (missing
 *    tshark, copy/exec error, timeout) falls back to the Kotlin result with an explanatory note.
 */
class AnalyzePcapUseCase(
    private val runShellCommand: RunShellCommandUseCase,
    private val resourceProvider: ResourceProvider,
    private val ensureTshark: EnsureTsharkUseCase,
    private val parser: PcapParser = PcapParser()
) {
    suspend operator fun invoke(pcapPath: String, keylogPath: String = ""): PcapAnalysis {
        val baseline = analyzeWithKotlin(pcapPath)
        if (!baseline.available) {
            return baseline
        }
        return when (ensureTshark()) {
            TsharkStatus.NO_CHROOT -> baseline
            TsharkStatus.NO_TSHARK -> baseline.copy(
                note = mergeNote(baseline.note, resourceProvider.getString(R.string.loot_pcap_hint_install_tshark))
            )
            TsharkStatus.READY -> {
                val http = runTshark(pcapPath, keylogPath.trim())
                if (http == null) {
                    baseline.copy(
                        note = mergeNote(baseline.note, resourceProvider.getString(R.string.loot_pcap_hint_tshark_failed))
                    )
                } else {
                    baseline.copy(
                        engine = PcapEngine.TSHARK,
                        decrypted = keylogPath.isNotBlank(),
                        http = if (http.isNotEmpty()) http else baseline.http
                    )
                }
            }
        }
    }

    private suspend fun analyzeWithKotlin(pcapPath: String): PcapAnalysis {
        val path = pcapPath.trim()
        if (path.isBlank()) {
            return PcapAnalysis(available = false, note = "no capture path")
        }
        // Guard memory before reading: the file is base64'd through a shell, so the whole capture
        // lands on the heap ~3x over (shell output string + filtered copy + decoded bytes). A large
        // capture would OOM the phone, so refuse oversized files up front and point at tshark instead.
        val sizeBytes = fileSizeBytes(path)
        if (sizeBytes != null) {
            oversizeCaptureNote(sizeBytes)?.let { note ->
                return PcapAnalysis(available = false, note = note)
            }
        }
        val result = runShellCommand(
            command = "base64 ${singleQuote(path)} 2>/dev/null",
            asRoot = true,
            timeoutMs = ANALYZE_TIMEOUT_MS
        )
        if (result.timedOut) {
            return PcapAnalysis(available = false, note = "read timed out (capture may be large)")
        }
        if (result.exitCode != null && result.exitCode != 0) {
            return PcapAnalysis(available = false, note = "could not read capture (root required?)")
        }
        val encoded = result.output.filterNot { it.isWhitespace() }
        if (encoded.isEmpty()) {
            return PcapAnalysis(available = false, note = "capture is empty")
        }
        val bytes = try {
            Base64.getMimeDecoder().decode(encoded)
        } catch (e: Exception) {
            return PcapAnalysis(available = false, note = "decode failed: ${e.message}")
        }
        return parser.parse(bytes)
    }

    /** Runs tshark inside the chroot, returning lifted HTTP messages, or null if the attempt failed. */
    private suspend fun runTshark(pcapPath: String, keylogPath: String): List<PcapHttpMessage>? {
        val hasKey = keylogPath.isNotBlank()
        val script = buildString {
            append("D=").append(EnsureTsharkUseCase.CHROOT_DIR).append("\n")
            append("cp ").append(singleQuote(pcapPath)).append(" \"\$D/tmp/").append(VIEW_PCAP).append("\" 2>/dev/null || exit 20\n")
            if (hasKey) {
                append("cp ").append(singleQuote(keylogPath)).append(" \"\$D/tmp/").append(KEYLOG_FILE).append("\" 2>/dev/null\n")
            }
            append("echo ").append(MARK_HTTP).append("\n")
            append("chroot \"\$D\" ").append(TSHARK_BIN).append(" -r /tmp/").append(VIEW_PCAP)
            if (hasKey) append(" -o tls.keylog_file:/tmp/").append(KEYLOG_FILE)
            append(" -Y 'http.request || http.response' -T fields -E separator=/t")
            for (field in FIELDS) {
                append(" -e ").append(field)
            }
            append(" 2>/dev/null\n")
            append("echo ").append(MARK_DONE).append("\n")
            append("rm -f \"\$D/tmp/").append(VIEW_PCAP).append("\" \"\$D/tmp/").append(KEYLOG_FILE).append("\" 2>/dev/null\n")
        }
        val result = runShellCommand(command = script, asRoot = true, timeoutMs = TSHARK_TIMEOUT_MS)
        if (result.timedOut) return null
        val out = result.output
        if (!out.contains(MARK_HTTP) || !out.contains(MARK_DONE)) return null
        val body = out.substringAfter(MARK_HTTP).substringBefore(MARK_DONE)
        return parseTsharkHttp(body)
    }

    private fun parseTsharkHttp(body: String): List<PcapHttpMessage> {
        return body.lineSequence()
            .map { it.trimEnd('\r') }
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val p = line.split('\t')
                val method = p.getOrElse(4) { "" }.trim()
                val uri = p.getOrElse(5) { "" }.trim()
                val host = p.getOrElse(6) { "" }.trim()
                val code = p.getOrElse(7) { "" }.trim()
                val ctype = p.getOrElse(8) { "" }.trim()
                when {
                    method.isNotBlank() -> PcapHttpMessage(
                        isRequest = true,
                        method = method,
                        host = host,
                        uri = uri,
                        contentType = ctype,
                        summaryLine = "→ $method ${if (host.isNotBlank() && !uri.startsWith("http")) host else ""}$uri".replace("  ", " ").trim()
                    )
                    code.isNotBlank() -> PcapHttpMessage(
                        isRequest = false,
                        statusCode = code,
                        contentType = ctype,
                        summaryLine = "← HTTP $code ${ctype}".trim()
                    )
                    else -> null
                }
            }
            .take(MAX_HTTP)
            .toList()
    }

    /** Returns the capture's size in bytes via a root `wc -c`, or null if it can't be determined. */
    private suspend fun fileSizeBytes(path: String): Long? {
        val result = runShellCommand(
            command = "wc -c < ${singleQuote(path)} 2>/dev/null",
            asRoot = true,
            timeoutMs = SIZE_PROBE_TIMEOUT_MS
        )
        if (result.timedOut || (result.exitCode != null && result.exitCode != 0)) {
            return null
        }
        return result.output.trim().toLongOrNull()
    }

    private fun mergeNote(existing: String, added: String): String =
        if (existing.isBlank()) added else "$existing · $added"

    private fun singleQuote(value: String): String = "'" + value.replace("'", "'\"'\"'") + "'"

    companion object {
        private const val ANALYZE_TIMEOUT_MS = 20_000L
        private const val SIZE_PROBE_TIMEOUT_MS = 5_000L
        private const val TSHARK_TIMEOUT_MS = 30_000L
        private const val MAX_HTTP = 500

        private const val BYTES_PER_MB = 1024L * 1024L

        /** The in-memory Kotlin engine refuses captures past this size to avoid OOM (see [analyzeWithKotlin]). */
        internal const val MAX_CAPTURE_BYTES = 64L * BYTES_PER_MB

        /**
         * Returns an explanatory note when [sizeBytes] exceeds [MAX_CAPTURE_BYTES], or null when the
         * capture is small enough to load. Pure so it can be unit-tested without a shell.
         */
        internal fun oversizeCaptureNote(sizeBytes: Long): String? =
            if (sizeBytes > MAX_CAPTURE_BYTES) {
                "capture too large (${sizeBytes / BYTES_PER_MB} MB > ${MAX_CAPTURE_BYTES / BYTES_PER_MB} MB) — analyze with tshark or on a desktop"
            } else {
                null
            }
        private const val VIEW_PCAP = "fsploit-view.pcap"
        private const val KEYLOG_FILE = "fsploit-keylog.txt"
        private const val TSHARK_BIN = "/usr/bin/tshark"
        private const val MARK_HTTP = "__FSPLOIT_PCAP_HTTP__"
        private const val MARK_DONE = "__FSPLOIT_PCAP_DONE__"
        private val FIELDS = listOf(
            "frame.time_relative",
            "tcp.stream",
            "ip.src",
            "ip.dst",
            "http.request.method",
            "http.request.full_uri",
            "http.host",
            "http.response.code",
            "http.content_type"
        )
    }
}
