package org.fsploit.android.data.pcap

import org.fsploit.android.domain.model.PcapEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class PcapParserTest {

    private val parser = PcapParser()

    @Test
    fun `too-small input is reported unavailable`() {
        val analysis = parser.parse(ByteArray(10))
        assertFalse(analysis.available)
        assertEquals("capture too small", analysis.note)
    }

    @Test
    fun `unrecognized magic is reported unavailable`() {
        val bytes = ByteArray(64) { 0x55 }
        val analysis = parser.parse(bytes)
        assertFalse(analysis.available)
        assertEquals("unrecognized capture format", analysis.note)
    }

    @Test
    fun `classic big-endian capture with one http get is fully dissected`() {
        val payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
        val pcap = classicPcapBigEndian(
            ethernetIpv4Tcp(
                srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 10),
                dstIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34),
                srcPort = 49152,
                dstPort = 80,
                payload = payload.toByteArray(Charsets.ISO_8859_1)
            )
        )

        val analysis = parser.parse(pcap)

        assertTrue(analysis.available)
        assertEquals(PcapEngine.KOTLIN, analysis.engine)
        assertEquals(1, analysis.totalPackets)

        val flow = analysis.flows.single()
        assertEquals("TCP", flow.proto)
        assertEquals("192.168.1.10", flow.src)
        assertEquals(49152, flow.srcPort)
        assertEquals("93.184.216.34", flow.dst)
        assertEquals(80, flow.dstPort)

        val http = analysis.http.single()
        assertTrue(http.isRequest)
        assertEquals("GET", http.method)
        assertEquals("example.com", http.host)
        assertEquals("/index.html", http.uri)
    }

    @Test
    fun `both directions of one conversation merge into a single flow`() {
        val req = ethernetIpv4Tcp(
            srcIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 10),
            dstIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34),
            srcPort = 49152,
            dstPort = 80,
            payload = "GET / HTTP/1.1\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        )
        val resp = ethernetIpv4Tcp(
            srcIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34),
            dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 10),
            srcPort = 80,
            dstPort = 49152,
            payload = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n".toByteArray(Charsets.ISO_8859_1)
        )

        val analysis = parser.parse(classicPcapBigEndian(req, resp))

        assertEquals(2, analysis.totalPackets)
        assertEquals("two directions collapse to one bidirectional flow", 1, analysis.flows.size)
        assertEquals(2, analysis.flows.single().packets)
        // The GET request and the 200 response are both lifted out.
        assertEquals(2, analysis.http.size)
        assertTrue(analysis.http.any { it.isRequest && it.method == "GET" })
        assertTrue(analysis.http.any { !it.isRequest && it.statusCode == "200" })
    }

    // ---- builders ---------------------------------------------------------

    /** Wraps one or more raw Ethernet frames into a classic (big-endian, microsecond) pcap file. */
    private fun classicPcapBigEndian(vararg frames: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        // Global header: magic a1b2c3d4, version 2.4, zone/sigfigs 0, snaplen 65535, linktype 1 (EN10MB).
        out.write(beU32(0xA1B2C3D4))
        out.write(beU16(2)); out.write(beU16(4))
        out.write(beU32(0)); out.write(beU32(0))
        out.write(beU32(65535))
        out.write(beU32(1))
        var tsSec = 1L
        for (frame in frames) {
            out.write(beU32(tsSec))      // ts_sec
            out.write(beU32(0))          // ts_usec
            out.write(beU32(frame.size.toLong())) // incl_len
            out.write(beU32(frame.size.toLong())) // orig_len
            out.write(frame)
            tsSec++
        }
        return out.toByteArray()
    }

    /** Builds an Ethernet/IPv4/TCP frame carrying [payload]. Checksums are left zero (parser ignores them). */
    private fun ethernetIpv4Tcp(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val out = ByteArrayOutputStream()
        // Ethernet header: dst mac, src mac, ethertype 0x0800 (IPv4).
        out.write(ByteArray(6) { 0x11 })
        out.write(ByteArray(6) { 0x22 })
        out.write(beU16(0x0800))

        val tcp = ByteArrayOutputStream()
        tcp.write(beU16(srcPort))
        tcp.write(beU16(dstPort))
        tcp.write(beU32(0))            // seq
        tcp.write(beU32(0))            // ack
        tcp.write(0x50)               // data offset = 5 words (20 bytes), reserved
        tcp.write(0x18)               // flags: PSH + ACK
        tcp.write(beU16(65535))        // window
        tcp.write(beU16(0))            // checksum
        tcp.write(beU16(0))            // urgent ptr
        tcp.write(payload)
        val tcpBytes = tcp.toByteArray()

        val ipTotalLength = 20 + tcpBytes.size
        out.write(0x45)               // version 4, IHL 5
        out.write(0x00)               // DSCP/ECN
        out.write(beU16(ipTotalLength))
        out.write(beU16(0))            // identification
        out.write(beU16(0))            // flags + fragment offset
        out.write(0x40)               // TTL 64
        out.write(0x06)               // protocol 6 (TCP)
        out.write(beU16(0))            // header checksum
        out.write(srcIp)
        out.write(dstIp)
        out.write(tcpBytes)
        return out.toByteArray()
    }

    private fun beU16(value: Int): ByteArray =
        byteArrayOf(((value ushr 8) and 0xFF).toByte(), (value and 0xFF).toByte())

    private fun beU32(value: Long): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte()
    )

    private fun beU32(value: Int): ByteArray = beU32(value.toLong() and 0xFFFFFFFFL)
}
