package org.fsploit.android.core

import org.fsploit.android.domain.model.DeviceRole
import org.fsploit.android.domain.model.HostFingerprint
import org.fsploit.android.domain.model.OsFamily

/**
 * Pure, offline host fingerprint heuristics. OS family comes mainly from the reply TTL
 * (Linux/Unix initial 64, Windows 128, network gear 255 — minus a few LAN hops), with
 * open-port signatures filling in device roles and refining the OS guess when no TTL is
 * available. Everything here is a guess, never authoritative.
 */
object HostFingerprinter {

    fun fingerprint(openPorts: List<Int>, ttl: Int?): HostFingerprint {
        val ports = openPorts.toHashSet()
        val roles = LinkedHashSet<DeviceRole>()

        if (3389 in ports) roles += DeviceRole.REMOTE_DESKTOP
        if (445 in ports || 139 in ports) roles += DeviceRole.SMB_SHARE
        if (22 in ports) roles += DeviceRole.SSH
        if (ports.any { it in CAMERA_PORTS }) roles += DeviceRole.IP_CAMERA
        if (ports.any { it in PRINTER_PORTS }) roles += DeviceRole.PRINTER
        if (ports.any { it in NAS_PORTS }) roles += DeviceRole.NAS
        if (ports.any { it in DATABASE_PORTS }) roles += DeviceRole.DATABASE
        if (23 in ports) roles += DeviceRole.IOT_TELNET
        if (53 in ports) roles += DeviceRole.ROUTER_DNS
        if (62078 in ports) roles += DeviceRole.APPLE_DEVICE
        if (ports.any { it in WEB_PORTS }) roles += DeviceRole.WEB_SERVER

        return HostFingerprint(
            osFamily = resolveOsFamily(ttl, ports),
            ttl = ttl,
            roles = roles.toList()
        )
    }

    private fun resolveOsFamily(ttl: Int?, ports: Set<Int>): OsFamily {
        if (62078 in ports) {
            return OsFamily.APPLE
        }
        val ttlFamily = when {
            ttl == null -> null
            ttl > 128 -> OsFamily.NETWORK_DEVICE
            ttl > 64 -> OsFamily.WINDOWS
            ttl > 32 -> OsFamily.LINUX_UNIX
            else -> null
        }
        if (ttlFamily != null) {
            return ttlFamily
        }
        return when {
            3389 in ports || 445 in ports || 139 in ports -> OsFamily.WINDOWS
            22 in ports -> OsFamily.LINUX_UNIX
            else -> OsFamily.UNKNOWN
        }
    }

    private val CAMERA_PORTS = setOf(554, 8554, 37777, 34567)
    private val PRINTER_PORTS = setOf(9100, 515, 631)
    private val NAS_PORTS = setOf(5000, 5001, 548)
    private val DATABASE_PORTS = setOf(3306, 5432, 1433, 1521, 27017, 6379)
    private val WEB_PORTS = setOf(80, 443, 8080, 8443)
}
