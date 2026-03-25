package org.fsploit.android.data.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import org.fsploit.android.domain.model.InterfaceCategory
import org.fsploit.android.domain.model.NetworkInterfaceInfo
import org.fsploit.android.domain.model.NetworkOverview
import org.fsploit.android.domain.model.SweepTarget
import java.net.Inet4Address
import java.net.InterfaceAddress
import java.net.NetworkInterface
import kotlin.math.max

class NetworkInterfaceRepository(
    context: Context
) {
    private val appContext = context.applicationContext
    private val connectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    fun loadOverview(): NetworkOverview {
        val interfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { isUsableInterface(it) }
            .sortedWith(compareBy<NetworkInterface> { interfacePriority(it.name) }.thenBy { it.name })
            .map { networkInterface ->
                val primaryAddress = usableIpv4InterfaceAddresses(networkInterface).firstOrNull()
                NetworkInterfaceInfo(
                    name = networkInterface.name,
                    addresses = usableIpv4Addresses(networkInterface),
                    category = classify(networkInterface.name),
                    primaryAddress = primaryAddress?.address?.hostAddress,
                    prefixLength = primaryAddress?.networkPrefixLength?.toInt()
                )
            }

        val activeTransportLabel = buildActiveTransportLabel()
        val statusMessage = if (interfaces.isEmpty()) {
            "No usable local IPv4 interface was found. Wi-Fi, Ethernet, or USB tethering must be active."
        } else {
            "Ready to build scanners and tooling on top of ${interfaces.first().name}."
        }

        return NetworkOverview(
            activeTransportLabel = activeTransportLabel,
            interfaces = interfaces,
            statusMessage = statusMessage
        )
    }

    private fun buildActiveTransportLabel(): String {
        val capabilities = connectivityManager.getNetworkCapabilities(connectivityManager.activeNetwork)
            ?: return "Offline"

        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet / USB"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
            else -> "Connected"
        }
    }

    private fun isUsableInterface(networkInterface: NetworkInterface): Boolean {
        if (!networkInterface.isUp || networkInterface.isLoopback) {
            return false
        }
        if (isIgnoredInterfaceName(networkInterface.name)) {
            return false
        }
        return usableIpv4InterfaceAddresses(networkInterface).isNotEmpty()
    }

    private fun usableIpv4Addresses(networkInterface: NetworkInterface): List<String> {
        return usableIpv4InterfaceAddresses(networkInterface)
            .mapNotNull { it.address.hostAddress }
            .filter { it.isNotBlank() }
    }

    private fun usableIpv4InterfaceAddresses(networkInterface: NetworkInterface): List<InterfaceAddress> {
        return networkInterface.interfaceAddresses.orEmpty()
            .filter { it.address is Inet4Address }
            .filterNot { it.address.isLoopbackAddress || it.address.isLinkLocalAddress }
    }

    private fun isIgnoredInterfaceName(name: String?): Boolean {
        if (name.isNullOrBlank()) {
            return true
        }

        val lower = name.lowercase()
        return lower.startsWith("lo") ||
            lower.startsWith("dummy") ||
            lower.startsWith("tun") ||
            lower.startsWith("rmnet") ||
            lower.startsWith("sit") ||
            lower.startsWith("ip6tnl") ||
            lower.startsWith("clat")
    }

    private fun interfacePriority(name: String): Int {
        val lower = name.lowercase()
        return when {
            lower.startsWith("wlan") || lower.startsWith("wifi") || lower.startsWith("ap") -> 0
            lower.startsWith("eth") || lower.startsWith("en") -> 1
            lower.startsWith("rndis") -> 2
            else -> 3
        }
    }

    private fun classify(name: String): InterfaceCategory {
        val lower = name.lowercase()
        return when {
            lower.startsWith("wlan") || lower.startsWith("wifi") || lower.startsWith("ap") -> InterfaceCategory.WIFI
            lower.startsWith("eth") || lower.startsWith("en") -> InterfaceCategory.ETHERNET
            lower.startsWith("rndis") -> InterfaceCategory.USB
            else -> InterfaceCategory.OTHER
        }
    }

    fun resolveSweepTarget(preferredInterfaceName: String): SweepTarget? {
        val interfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { isUsableInterface(it) }
            .sortedWith(compareBy<NetworkInterface> { interfacePriority(it.name) }.thenBy { it.name })

        val chosenInterface = interfaces.firstOrNull { it.name == preferredInterfaceName }
            ?: interfaces.firstOrNull()
            ?: return null

        val interfaceAddress = usableIpv4InterfaceAddresses(chosenInterface).firstOrNull() ?: return null
        val localAddress = interfaceAddress.address.hostAddress ?: return null
        val rawPrefix = interfaceAddress.networkPrefixLength.toInt()
        val effectivePrefix = max(rawPrefix, 24)
        val hostCandidates = buildHostCandidates(localAddress, effectivePrefix)
            .filterNot { it == localAddress }
            .take(64)

        return SweepTarget(
            interfaceName = chosenInterface.name,
            localAddress = localAddress,
            prefixLength = effectivePrefix,
            networkAddress = calculateNetworkAddress(localAddress, effectivePrefix),
            hostCandidates = hostCandidates
        )
    }

    private fun buildHostCandidates(localAddress: String, prefixLength: Int): List<String> {
        val localInt = ipv4ToInt(localAddress)
        val mask = prefixToMask(prefixLength)
        val network = localInt and mask
        val broadcast = network or mask.inv()
        val start = network + 1
        val end = broadcast - 1

        if (end < start) {
            return emptyList()
        }

        return (start..end).map(::intToIpv4)
    }

    private fun calculateNetworkAddress(localAddress: String, prefixLength: Int): String {
        val address = ipv4ToInt(localAddress)
        return intToIpv4(address and prefixToMask(prefixLength))
    }

    private fun prefixToMask(prefixLength: Int): Int {
        return if (prefixLength <= 0) {
            0
        } else {
            (-0x1 shl (32 - prefixLength))
        }
    }

    private fun ipv4ToInt(address: String): Int {
        val octets = address.split('.').map { it.toInt() }
        return (octets[0] shl 24) or
            (octets[1] shl 16) or
            (octets[2] shl 8) or
            octets[3]
    }

    private fun intToIpv4(value: Int): String {
        val unsigned = value.toLong() and 0xffffffffL
        return listOf(
            (unsigned shr 24) and 0xff,
            (unsigned shr 16) and 0xff,
            (unsigned shr 8) and 0xff,
            unsigned and 0xff
        ).joinToString(".")
    }
}
