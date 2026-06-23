package org.fsploit.android.core

import org.fsploit.android.domain.model.NetworkInterfaceInfo

/** IPv4 helpers shared by the session and MITM layers (moved verbatim out of the old HomeViewModel). */
object IpUtils {

    fun parseIpv4(address: String): IntArray? {
        val octets = address.split('.')
        if (octets.size != 4) {
            return null
        }
        val parsed = IntArray(4)
        for (index in octets.indices) {
            val value = octets[index].toIntOrNull() ?: return null
            if (value !in 0..255) {
                return null
            }
            parsed[index] = value
        }
        return parsed
    }

    fun isValidManualHost(address: String): Boolean = parseIpv4(address.trim()) != null

    fun isHostOnInterfaceSubnet(
        hostAddress: String,
        networkInterface: NetworkInterfaceInfo
    ): Boolean {
        val localAddress = networkInterface.primaryAddress ?: return false
        val prefixLength = networkInterface.prefixLength ?: return false
        val hostOctets = parseIpv4(hostAddress) ?: return false
        val localOctets = parseIpv4(localAddress) ?: return false
        val fullBytes = prefixLength / 8
        val partialBits = prefixLength % 8
        for (index in 0 until fullBytes) {
            if (hostOctets[index] != localOctets[index]) {
                return false
            }
        }
        if (partialBits == 0) {
            return true
        }
        val mask = (0xFF shl (8 - partialBits)) and 0xFF
        return (hostOctets[fullBytes] and mask) == (localOctets[fullBytes] and mask)
    }
}
