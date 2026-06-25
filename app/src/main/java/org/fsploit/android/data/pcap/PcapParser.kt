package org.fsploit.android.data.pcap

import org.fsploit.android.domain.model.PcapAnalysis
import org.fsploit.android.domain.model.PcapEngine
import org.fsploit.android.domain.model.PcapFlow
import org.fsploit.android.domain.model.PcapHttpMessage
import org.fsploit.android.domain.model.PcapPacket

/**
 * A deliberately lenient pure-Kotlin pcap / pcapng reader. It dissects Ethernet/RAW-IP/Linux-SLL →
 * IPv4/IPv6 → TCP/UDP far enough to build a flow table, lift cleartext HTTP request/response lines,
 * and list packets — no external tool required. It never decrypts TLS (that needs tshark + a keylog).
 *
 * Robustness over completeness: a malformed packet is skipped, and a file we cannot make sense of
 * returns [PcapAnalysis.available] = false with a [PcapAnalysis.note] rather than throwing.
 */
class PcapParser {

    fun parse(bytes: ByteArray): PcapAnalysis {
        return try {
            when {
                bytes.size < 24 -> PcapAnalysis(available = false, note = "capture too small")
                isPcapNg(bytes) -> parsePcapNg(bytes)
                isClassicPcap(bytes) -> parseClassicPcap(bytes)
                else -> PcapAnalysis(available = false, note = "unrecognized capture format")
            }
        } catch (e: Exception) {
            PcapAnalysis(available = false, note = "parse error: ${e.message}")
        }
    }

    // ---- format detection -------------------------------------------------

    private fun isClassicPcap(b: ByteArray): Boolean {
        val m = u32be(b, 0)
        return m == 0xa1b2c3d4L || m == 0xd4c3b2a1L || m == 0xa1b23c4dL || m == 0x4d3cb2a1L
    }

    private fun isPcapNg(b: ByteArray): Boolean = u32be(b, 0) == 0x0a0d0d0aL

    // ---- classic pcap -----------------------------------------------------

    private fun parseClassicPcap(b: ByteArray): PcapAnalysis {
        val magic = u32be(b, 0)
        val little = magic == 0xd4c3b2a1L || magic == 0x4d3cb2a1L
        val nanos = magic == 0xa1b23c4dL || magic == 0x4d3cb2a1L
        val linkType = u32(b, 20, little).toInt()

        val acc = Accumulator()
        var off = 24
        while (off + 16 <= b.size) {
            val tsSec = u32(b, off, little)
            val tsFrac = u32(b, off + 4, little)
            val inclLen = u32(b, off + 8, little).toInt()
            off += 16
            if (inclLen < 0 || off + inclLen > b.size) break
            val tsMs = tsSec * 1000L + if (nanos) tsFrac / 1_000_000L else tsFrac / 1000L
            acc.consume(b, off, inclLen, linkType, tsMs)
            off += inclLen
        }
        return acc.toAnalysis()
    }

    // ---- pcapng (best effort) ---------------------------------------------

    private fun parsePcapNg(b: ByteArray): PcapAnalysis {
        // Section header block fixes byte order via its magic at offset 8.
        val little = u32be(b, 8) == 0x4d3c2b1aL // 0x1A2B3C4D stored little-endian
        val acc = Accumulator()
        val ifaceLinkTypes = ArrayList<Int>()
        var off = 0
        while (off + 12 <= b.size) {
            val blockType = u32(b, off, little)
            val totalLen = u32(b, off + 4, little).toInt()
            if (totalLen < 12 || off + totalLen > b.size) break
            when (blockType) {
                0x00000001L -> { // Interface Description Block: linktype(2), reserved(2), snaplen(4)
                    ifaceLinkTypes.add(u16(b, off + 8, little))
                }
                0x00000006L -> { // Enhanced Packet Block
                    val ifaceId = u32(b, off + 8, little).toInt()
                    val tsHigh = u32(b, off + 12, little)
                    val tsLow = u32(b, off + 16, little)
                    val capLen = u32(b, off + 20, little).toInt()
                    val ts = (tsHigh shl 32) or tsLow
                    val tsMs = ts / 1000L // assume default microsecond resolution
                    val dataOff = off + 28
                    val link = ifaceLinkTypes.getOrElse(ifaceId) { 1 }
                    if (capLen in 0..(b.size - dataOff)) {
                        acc.consume(b, dataOff, capLen, link, tsMs)
                    }
                }
                0x00000003L -> { // Simple Packet Block: orig_len(4), data
                    val capLen = (totalLen - 16).coerceAtLeast(0)
                    val link = ifaceLinkTypes.getOrElse(0) { 1 }
                    if (off + 12 + capLen <= b.size) {
                        acc.consume(b, off + 12, capLen, link, 0L)
                    }
                }
            }
            off += totalLen
        }
        return acc.toAnalysis()
    }

    // ---- per-packet dissection + aggregation ------------------------------

    private class Accumulator {
        private val flows = LinkedHashMap<String, MutableFlow>()
        private val http = ArrayList<PcapHttpMessage>()
        private val packets = ArrayList<PcapPacket>()
        private var total = 0
        private var firstTs = -1L
        private var truncated = false

        fun consume(b: ByteArray, start: Int, len: Int, linkType: Int, tsMs: Long) {
            total++
            if (firstTs < 0) firstTs = tsMs
            val rel = (tsMs - firstTs).coerceAtLeast(0)
            try {
                val ipOff = stripLink(b, start, len, linkType) ?: return logPacket(rel, "", "", "L2", len, "non-IP")
                dissectIp(b, ipOff, start + len, len, rel)
            } catch (_: Exception) {
                // keep going; a bad packet shouldn't kill the capture
            }
        }

        /** Returns the offset where the IP header starts, or null for frames we don't carry up. */
        private fun stripLink(b: ByteArray, start: Int, len: Int, linkType: Int): Int? {
            return when (linkType) {
                1 -> { // EN10MB
                    if (len < 14) return null
                    var etherType = u16be(b, start + 12)
                    var hdr = 14
                    if (etherType == 0x8100 || etherType == 0x88a8) { // VLAN tag
                        if (len < 18) return null
                        etherType = u16be(b, start + 16)
                        hdr = 18
                    }
                    when (etherType) {
                        0x0800, 0x86dd -> start + hdr
                        else -> null
                    }
                }
                101 -> start // RAW IP
                113 -> if (len >= 16) start + 16 else null // Linux SLL
                12, 14 -> start // RAW IPv4/IPv6 (some captures)
                else -> start // best effort: assume it starts with IP
            }
        }

        private fun dissectIp(b: ByteArray, ipOff: Int, frameEnd: Int, frameLen: Int, rel: Long) {
            if (ipOff >= frameEnd) return
            val version = (b[ipOff].toInt() ushr 4) and 0x0F
            when (version) {
                4 -> {
                    val ihl = (b[ipOff].toInt() and 0x0F) * 4
                    if (ihl < 20 || ipOff + ihl > frameEnd) return
                    val proto = b[ipOff + 9].toInt() and 0xFF
                    val src = ipv4(b, ipOff + 12)
                    val dst = ipv4(b, ipOff + 16)
                    dissectTransport(b, ipOff + ihl, frameEnd, proto, src, dst, frameLen, rel)
                }
                6 -> {
                    if (ipOff + 40 > frameEnd) return
                    val proto = b[ipOff + 6].toInt() and 0xFF
                    val src = ipv6(b, ipOff + 8)
                    val dst = ipv6(b, ipOff + 24)
                    dissectTransport(b, ipOff + 40, frameEnd, proto, src, dst, frameLen, rel)
                }
                else -> return
            }
        }

        private fun dissectTransport(
            b: ByteArray, l4: Int, frameEnd: Int, proto: Int,
            src: String, dst: String, frameLen: Int, rel: Long
        ) {
            when (proto) {
                6 -> { // TCP
                    if (l4 + 20 > frameEnd) return
                    val sport = u16be(b, l4)
                    val dport = u16be(b, l4 + 2)
                    val dataOff = ((b[l4 + 12].toInt() ushr 4) and 0x0F) * 4
                    val payloadStart = l4 + dataOff
                    addFlow("TCP", src, sport, dst, dport, frameLen)
                    val flags = b[l4 + 13].toInt() and 0xFF
                    val info = "tcp $sport→$dport ${tcpFlags(flags)}"
                    logPacket(rel, "$src:$sport", "$dst:$dport", "TCP", frameLen, info)
                    if (payloadStart < frameEnd) {
                        sniffHttp(b, payloadStart, frameEnd, src, sport, dst, dport)
                    }
                }
                17 -> { // UDP
                    if (l4 + 8 > frameEnd) return
                    val sport = u16be(b, l4)
                    val dport = u16be(b, l4 + 2)
                    addFlow("UDP", src, sport, dst, dport, frameLen)
                    logPacket(rel, "$src:$sport", "$dst:$dport", "UDP", frameLen, "udp $sport→$dport")
                }
                1 -> { addFlow("ICMP", src, 0, dst, 0, frameLen); logPacket(rel, src, dst, "ICMP", frameLen, "icmp") }
                58 -> { addFlow("ICMPv6", src, 0, dst, 0, frameLen); logPacket(rel, src, dst, "ICMPv6", frameLen, "icmpv6") }
                else -> { addFlow("IP/$proto", src, 0, dst, 0, frameLen); logPacket(rel, src, dst, "IP", frameLen, "proto $proto") }
            }
        }

        private fun sniffHttp(b: ByteArray, start: Int, end: Int, src: String, sport: Int, dst: String, dport: Int) {
            if (http.size >= MAX_HTTP) return
            val n = (end - start).coerceAtMost(2048)
            if (n < 16) return
            // Only the leading bytes; HTTP start lines are ASCII.
            val text = String(b, start, n, Charsets.ISO_8859_1)
            val firstLineEnd = text.indexOf("\r\n").let { if (it < 0) text.length else it }
            val firstLine = text.substring(0, firstLineEnd)
            if (firstLine.startsWith("HTTP/1.")) {
                val code = firstLine.substringAfter(' ', "").trim().substringBefore(' ')
                if (code.isNotBlank()) {
                    http.add(
                        PcapHttpMessage(
                            isRequest = false,
                            statusCode = code,
                            contentType = headerValue(text, "Content-Type"),
                            summaryLine = "← $dst:$dport  $firstLine"
                        )
                    )
                }
                return
            }
            val method = HTTP_METHODS.firstOrNull { firstLine.startsWith("$it ") } ?: return
            if (!firstLine.contains(" HTTP/1.")) return
            val uri = firstLine.removePrefix("$method ").substringBefore(" HTTP/")
            val host = headerValue(text, "Host")
            http.add(
                PcapHttpMessage(
                    isRequest = true,
                    method = method,
                    host = host,
                    uri = uri,
                    summaryLine = "→ $method ${if (host.isNotBlank()) "http://$host" else ""}$uri"
                )
            )
        }

        private fun headerValue(text: String, name: String): String {
            val lower = text.lowercase()
            val key = "\r\n${name.lowercase()}:"
            val at = lower.indexOf(key)
            if (at < 0) return ""
            val valStart = at + key.length
            val lineEnd = text.indexOf("\r\n", valStart).let { if (it < 0) text.length else it }
            return text.substring(valStart, lineEnd).trim()
        }

        private fun addFlow(proto: String, a: String, ap: Int, b: String, bp: Int, bytes: Int) {
            // Canonical key so both directions of one conversation merge.
            val left = "$a:$ap"
            val right = "$b:$bp"
            val key = if (left <= right) "$proto|$left|$right" else "$proto|$right|$left"
            val f = flows.getOrPut(key) {
                if (left <= right) MutableFlow(proto, a, ap, b, bp) else MutableFlow(proto, b, bp, a, ap)
            }
            f.packets++
            f.bytes += bytes
        }

        private fun logPacket(rel: Long, src: String, dst: String, proto: String, len: Int, info: String) {
            if (packets.size < MAX_PACKETS) {
                packets.add(PcapPacket(packets.size + 1, rel, src, dst, proto, len, info))
            } else {
                truncated = true
            }
        }

        fun toAnalysis(): PcapAnalysis {
            if (total == 0) {
                return PcapAnalysis(available = false, note = "no packets in capture")
            }
            val flowList = flows.values
                .sortedByDescending { it.bytes }
                .take(MAX_FLOWS)
                .map { PcapFlow(it.proto, it.src, it.srcPort, it.dst, it.dstPort, it.packets, it.bytes) }
            val note = if (truncated || flows.size > MAX_FLOWS || http.size >= MAX_HTTP) {
                "lists truncated for display"
            } else {
                ""
            }
            return PcapAnalysis(
                available = true,
                engine = PcapEngine.KOTLIN,
                decrypted = false,
                totalPackets = total,
                flows = flowList,
                http = http,
                packets = packets,
                note = note
            )
        }

        private fun tcpFlags(f: Int): String {
            val sb = StringBuilder()
            if (f and 0x02 != 0) sb.append("SYN ")
            if (f and 0x10 != 0) sb.append("ACK ")
            if (f and 0x01 != 0) sb.append("FIN ")
            if (f and 0x04 != 0) sb.append("RST ")
            if (f and 0x08 != 0) sb.append("PSH ")
            return sb.toString().trim()
        }
    }

    private class MutableFlow(
        val proto: String,
        val src: String,
        val srcPort: Int,
        val dst: String,
        val dstPort: Int
    ) {
        var packets = 0
        var bytes = 0L
    }

    companion object {
        private const val MAX_PACKETS = 2000
        private const val MAX_FLOWS = 200
        private const val MAX_HTTP = 500
        private val HTTP_METHODS = listOf("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT")

        // ---- byte readers ----
        private fun u32be(b: ByteArray, o: Int): Long =
            ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
                ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)

        private fun u32le(b: ByteArray, o: Int): Long =
            (b[o].toLong() and 0xFF) or ((b[o + 1].toLong() and 0xFF) shl 8) or
                ((b[o + 2].toLong() and 0xFF) shl 16) or ((b[o + 3].toLong() and 0xFF) shl 24)

        private fun u32(b: ByteArray, o: Int, little: Boolean): Long = if (little) u32le(b, o) else u32be(b, o)

        private fun u16be(b: ByteArray, o: Int): Int = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

        private fun u16le(b: ByteArray, o: Int): Int = (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

        private fun u16(b: ByteArray, o: Int, little: Boolean): Int = if (little) u16le(b, o) else u16be(b, o)

        private fun ipv4(b: ByteArray, o: Int): String =
            "${b[o].toInt() and 0xFF}.${b[o + 1].toInt() and 0xFF}.${b[o + 2].toInt() and 0xFF}.${b[o + 3].toInt() and 0xFF}"

        private fun ipv6(b: ByteArray, o: Int): String {
            val parts = ArrayList<String>(8)
            for (i in 0 until 8) {
                parts.add(Integer.toHexString(u16be(b, o + i * 2)))
            }
            return parts.joinToString(":")
        }
    }
}
