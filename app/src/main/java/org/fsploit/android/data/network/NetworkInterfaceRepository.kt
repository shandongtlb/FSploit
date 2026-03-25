package org.fsploit.android.data.network

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import org.fsploit.android.domain.model.InterfaceCategory
import org.fsploit.android.domain.model.NetworkInterfaceInfo
import org.fsploit.android.domain.model.NetworkOverview
import java.net.Inet4Address
import java.net.NetworkInterface

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
                NetworkInterfaceInfo(
                    name = networkInterface.name,
                    addresses = usableIpv4Addresses(networkInterface),
                    category = classify(networkInterface.name)
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
        return usableIpv4Addresses(networkInterface).isNotEmpty()
    }

    private fun usableIpv4Addresses(networkInterface: NetworkInterface): List<String> {
        return networkInterface.inetAddresses.toList()
            .filterIsInstance<Inet4Address>()
            .filterNot { it.isLoopbackAddress || it.isLinkLocalAddress }
            .map { it.hostAddress ?: "" }
            .filter { it.isNotBlank() }
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
}
