package org.fsploit.android.core

import org.fsploit.android.domain.model.DeviceRole
import org.fsploit.android.domain.model.OsFamily
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class HostFingerprinterTest {

    @Test
    fun `ttl 64 reads as linux unix`() {
        assertEquals(OsFamily.LINUX_UNIX, HostFingerprinter.fingerprint(emptyList(), ttl = 64).osFamily)
        // A couple of LAN hops off the initial 64 still lands in the 33..64 band.
        assertEquals(OsFamily.LINUX_UNIX, HostFingerprinter.fingerprint(emptyList(), ttl = 58).osFamily)
    }

    @Test
    fun `ttl 128 reads as windows and 255 as network device`() {
        assertEquals(OsFamily.WINDOWS, HostFingerprinter.fingerprint(emptyList(), ttl = 128).osFamily)
        assertEquals(OsFamily.WINDOWS, HostFingerprinter.fingerprint(emptyList(), ttl = 120).osFamily)
        assertEquals(OsFamily.NETWORK_DEVICE, HostFingerprinter.fingerprint(emptyList(), ttl = 255).osFamily)
    }

    @Test
    fun `apple device port overrides ttl-based os guess`() {
        // 62078 (iOS lockdownd) wins even when the TTL would say Windows.
        val fp = HostFingerprinter.fingerprint(listOf(62078), ttl = 128)
        assertEquals(OsFamily.APPLE, fp.osFamily)
        assertTrue(fp.roles.contains(DeviceRole.APPLE_DEVICE))
    }

    @Test
    fun `without ttl the os falls back to port signatures`() {
        assertEquals(OsFamily.WINDOWS, HostFingerprinter.fingerprint(listOf(445), ttl = null).osFamily)
        assertEquals(OsFamily.LINUX_UNIX, HostFingerprinter.fingerprint(listOf(22), ttl = null).osFamily)
        assertEquals(OsFamily.UNKNOWN, HostFingerprinter.fingerprint(listOf(12345), ttl = null).osFamily)
    }

    @Test
    fun `multiple roles are detected from a single port set`() {
        val roles = HostFingerprinter.fingerprint(listOf(22, 445, 80), ttl = 64).roles
        assertTrue(roles.contains(DeviceRole.SSH))
        assertTrue(roles.contains(DeviceRole.SMB_SHARE))
        assertTrue(roles.contains(DeviceRole.WEB_SERVER))
    }

    @Test
    fun `distinctive ports map to their roles`() {
        assertTrue(HostFingerprinter.fingerprint(listOf(554), null).roles.contains(DeviceRole.IP_CAMERA))
        assertTrue(HostFingerprinter.fingerprint(listOf(9100), null).roles.contains(DeviceRole.PRINTER))
        assertTrue(HostFingerprinter.fingerprint(listOf(3306), null).roles.contains(DeviceRole.DATABASE))
        assertTrue(HostFingerprinter.fingerprint(listOf(23), null).roles.contains(DeviceRole.IOT_TELNET))
        assertTrue(HostFingerprinter.fingerprint(listOf(3389), null).roles.contains(DeviceRole.REMOTE_DESKTOP))
    }

    @Test
    fun `no ports and no ttl is fully unknown`() {
        val fp = HostFingerprinter.fingerprint(emptyList(), ttl = null)
        assertEquals(OsFamily.UNKNOWN, fp.osFamily)
        assertTrue(fp.roles.isEmpty())
        assertEquals(null, fp.ttl)
    }

    @Test
    fun `ttl is echoed back on the fingerprint`() {
        assertEquals(64, HostFingerprinter.fingerprint(emptyList(), ttl = 64).ttl)
    }

    @Test
    fun `non-signature ports yield no roles`() {
        assertFalse(HostFingerprinter.fingerprint(listOf(49152, 50000), 64).roles.any { it == DeviceRole.WEB_SERVER })
    }
}
