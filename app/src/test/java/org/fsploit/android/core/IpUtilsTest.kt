package org.fsploit.android.core

import org.fsploit.android.domain.model.InterfaceCategory
import org.fsploit.android.domain.model.NetworkInterfaceInfo
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpUtilsTest {

    @Test
    fun `parseIpv4 accepts a well-formed dotted quad`() {
        assertArrayEquals(intArrayOf(192, 168, 1, 20), IpUtils.parseIpv4("192.168.1.20"))
        assertArrayEquals(intArrayOf(0, 0, 0, 0), IpUtils.parseIpv4("0.0.0.0"))
        assertArrayEquals(intArrayOf(255, 255, 255, 255), IpUtils.parseIpv4("255.255.255.255"))
    }

    @Test
    fun `parseIpv4 rejects out-of-range octets`() {
        assertNull(IpUtils.parseIpv4("256.0.0.1"))
        assertNull(IpUtils.parseIpv4("192.168.1.-1"))
    }

    @Test
    fun `parseIpv4 rejects wrong shape and non-numeric octets`() {
        assertNull(IpUtils.parseIpv4("192.168.1"))
        assertNull(IpUtils.parseIpv4("192.168.1.1.1"))
        assertNull(IpUtils.parseIpv4("192.168.1.x"))
        assertNull(IpUtils.parseIpv4(""))
    }

    @Test
    fun `isValidManualHost trims surrounding whitespace`() {
        assertTrue(IpUtils.isValidManualHost("  10.0.0.5  "))
        assertFalse(IpUtils.isValidManualHost("not-an-ip"))
    }

    @Test
    fun `host on same 24 subnet is recognized`() {
        val iface = wifi(primary = "192.168.1.10", prefix = 24)
        assertTrue(IpUtils.isHostOnInterfaceSubnet("192.168.1.200", iface))
        assertFalse(IpUtils.isHostOnInterfaceSubnet("192.168.2.200", iface))
    }

    @Test
    fun `prefix 16 ignores the last two octets`() {
        val iface = wifi(primary = "172.16.5.4", prefix = 16)
        assertTrue(IpUtils.isHostOnInterfaceSubnet("172.16.250.99", iface))
        assertFalse(IpUtils.isHostOnInterfaceSubnet("172.17.0.1", iface))
    }

    @Test
    fun `partial-byte prefix 20 masks the boundary octet`() {
        // /20 -> third octet masked with 0xF0. 16 (0001_0000) and 31 (0001_1111) share the top nibble.
        val iface = wifi(primary = "10.0.16.1", prefix = 20)
        assertTrue(IpUtils.isHostOnInterfaceSubnet("10.0.31.254", iface))
        assertFalse(IpUtils.isHostOnInterfaceSubnet("10.0.32.1", iface))
    }

    @Test
    fun `prefix 32 matches only the exact host`() {
        val iface = wifi(primary = "10.0.0.7", prefix = 32)
        assertTrue(IpUtils.isHostOnInterfaceSubnet("10.0.0.7", iface))
        assertFalse(IpUtils.isHostOnInterfaceSubnet("10.0.0.8", iface))
    }

    @Test
    fun `missing primary address or prefix returns false`() {
        val noPrefix = NetworkInterfaceInfo(
            name = "wlan0",
            addresses = listOf("192.168.1.10"),
            category = InterfaceCategory.WIFI,
            prefixLength = null
        )
        assertFalse(IpUtils.isHostOnInterfaceSubnet("192.168.1.11", noPrefix))

        val noAddress = NetworkInterfaceInfo(
            name = "wlan0",
            addresses = emptyList(),
            category = InterfaceCategory.WIFI,
            primaryAddress = null,
            prefixLength = 24
        )
        assertFalse(IpUtils.isHostOnInterfaceSubnet("192.168.1.11", noAddress))
    }

    @Test
    fun `malformed host address is rejected by subnet check`() {
        val iface = wifi(primary = "192.168.1.10", prefix = 24)
        assertFalse(IpUtils.isHostOnInterfaceSubnet("garbage", iface))
    }

    private fun wifi(primary: String, prefix: Int) = NetworkInterfaceInfo(
        name = "wlan0",
        addresses = listOf(primary),
        category = InterfaceCategory.WIFI,
        prefixLength = prefix
    )
}
