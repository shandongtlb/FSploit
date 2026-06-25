package org.fsploit.android.domain.model

/** Which engine produced a [PcapAnalysis]. */
enum class PcapEngine { KOTLIN, TSHARK }

/** One bidirectional transport flow aggregated from a capture. */
data class PcapFlow(
    val proto: String,
    val src: String,
    val srcPort: Int,
    val dst: String,
    val dstPort: Int,
    val packets: Int,
    val bytes: Long
)

/** A single HTTP request or response line lifted out of a capture (cleartext or decrypted). */
data class PcapHttpMessage(
    val isRequest: Boolean,
    val method: String = "",
    val host: String = "",
    val uri: String = "",
    val statusCode: String = "",
    val contentType: String = "",
    val summaryLine: String
)

/** One packet for the drill-down list. [tsMs] is relative to the first packet. */
data class PcapPacket(
    val index: Int,
    val tsMs: Long,
    val src: String,
    val dst: String,
    val proto: String,
    val length: Int,
    val info: String
)

/**
 * Result of analyzing a session's pcap at one point in time. [available] is false when the file
 * could not be read/parsed (then [note] explains why). [decrypted] is only ever true on the tshark
 * engine with an imported keylog. Lists are capped for the phone UI; truncation is recorded in [note].
 */
data class PcapAnalysis(
    val available: Boolean = false,
    val engine: PcapEngine = PcapEngine.KOTLIN,
    val decrypted: Boolean = false,
    val totalPackets: Int = 0,
    val flows: List<PcapFlow> = emptyList(),
    val http: List<PcapHttpMessage> = emptyList(),
    val packets: List<PcapPacket> = emptyList(),
    val note: String = ""
)
