package org.fsploit.android.data.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.fsploit.android.R
import org.fsploit.android.core.OuiLookup
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.HostScanResult
import org.fsploit.android.domain.model.HostSweepReport
import org.fsploit.android.domain.model.SweepTarget
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

class HostSweepRepository(
    private val networkInterfaceRepository: NetworkInterfaceRepository,
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository,
    private val ouiLookup: OuiLookup,
    private val nmapScanner: NmapScanner
) {
    suspend fun runSweep(
        preferredInterfaceName: String,
        onProgress: (scanned: Int, total: Int) -> Unit = { _, _ -> }
    ): HostSweepReport = coroutineScope {
        val target = networkInterfaceRepository.resolveSweepTarget(preferredInterfaceName)
            ?: return@coroutineScope HostSweepReport(
                interfaceName = "",
                subnetLabel = "",
                scannedHosts = 0,
                responsiveHosts = emptyList(),
                summary = resourceProvider.getString(R.string.host_sweep_unavailable)
            )

        // Prefer nmap's host discovery when the managed package is present (steadier timing, fewer
        // missed hosts); otherwise fall back to the zero-dependency builtin ARP/neighbor sweep so
        // discovery always works.
        val responsiveHosts = if (nmapScanner.isAvailable()) {
            nmapScanner.discoverHosts(target)
        } else {
            probeHosts(target, onProgress)
        }

        val subnetLabel = "${target.networkAddress}/${target.prefixLength}"
        val summary = if (responsiveHosts.isEmpty()) {
            resourceProvider.getString(R.string.host_sweep_none, target.interfaceName)
        } else {
            resourceProvider.getString(
                R.string.host_sweep_found,
                target.interfaceName,
                responsiveHosts.size
            )
        }

        HostSweepReport(
            interfaceName = target.interfaceName,
            subnetLabel = subnetLabel,
            scannedHosts = target.hostCandidates.size,
            responsiveHosts = responsiveHosts,
            summary = summary
        )
    }

    private suspend fun probeHosts(
        target: SweepTarget,
        onProgress: (scanned: Int, total: Int) -> Unit
    ): List<HostScanResult> = coroutineScope {
        val hosts = target.hostCandidates
        if (hosts.isEmpty()) {
            return@coroutineScope emptyList()
        }

        val neighborResults = runNeighborSweep(target, onProgress)
        val unresolvedHosts = hosts.filterNot { neighborResults.containsKey(it) }
        // TCP supplement is a niche fallback for small subnets; on a large sweep the ARP/neighbor
        // pass already catches every L2-reachable host, so skip the (very slow) per-host TCP probe.
        if (unresolvedHosts.isEmpty() || unresolvedHosts.size > TCP_SUPPLEMENT_MAX_HOSTS) {
            return@coroutineScope neighborResults.values.sortedBy { it.hostAddress }
        }

        val tcpResults = runTcpSupplement(unresolvedHosts)
        return@coroutineScope (neighborResults.values + tcpResults)
            .sortedBy { it.hostAddress }
    }

    private fun runNeighborSweep(
        target: SweepTarget,
        onProgress: (scanned: Int, total: Int) -> Unit
    ): Map<String, HostScanResult> {
        val total = target.hostCandidates.size
        val shellResult = shellRepository.execute(
            command = buildProbeCommand(target),
            asRoot = true,
            timeoutMs = sweepTimeoutMs(total),
            onLine = { line ->
                val trimmed = line.trim()
                when {
                    trimmed.startsWith(PROGRESS_MARKER) ->
                        trimmed.removePrefix(PROGRESS_MARKER).trim().toIntOrNull()?.let { scanned ->
                            onProgress(scanned.coerceAtMost(total), total)
                        }
                    trimmed == NEIGH_MARKER -> onProgress(total, total)
                }
            }
        )

        return parseProbeOutput(
            interfaceName = target.interfaceName,
            output = shellResult.output,
            knownHosts = target.hostCandidates.toSet()
        )
    }

    /** Scale the shell timeout to subnet size so large sweeps aren't cut off mid-run. */
    private fun sweepTimeoutMs(hostCount: Int): Long {
        return (SWEEP_TIMEOUT_BASE_MS + hostCount.toLong() * SWEEP_TIMEOUT_PER_HOST_MS)
            .coerceAtMost(SWEEP_TIMEOUT_MAX_MS)
    }

    private suspend fun runTcpSupplement(hosts: List<String>): List<HostScanResult> {
        return coroutineScope {
            val semaphore = Semaphore(TCP_PROBE_PARALLELISM)
            hosts.map { host ->
                async(Dispatchers.IO) {
                    semaphore.withPermit {
                        probeTcpReachability(host)
                    }
                }
            }.awaitAll().filterNotNull()
        }
    }

    private fun buildProbeCommand(target: SweepTarget): String {
        // Generate the ping range numerically inside the shell so the command stays a constant size
        // no matter how large the subnet (no inlined IP list -> no ARG_MAX ceiling). Pinging in
        // parallel waves primes the ARP/neighbor cache; it also forces ARP resolution, so hosts
        // that drop ICMP still surface in the neighbor table. The local address is skipped.
        val networkInt = ipv4ToLong(target.networkAddress)
        val hostBits = 32 - target.prefixLength
        val broadcastInt = networkInt or ((1L shl hostBits) - 1L)
        val startInt = networkInt + 1
        val endInt = broadcastInt - 1
        val localInt = ipv4ToLong(target.localAddress)

        return buildString {
            append("PATH=/system/bin:/system/xbin:\$PATH; ")
            append("s=").append(startInt)
            append("; e=").append(endInt)
            append("; l=").append(localInt)
            append("; c=0; ")
            append("while [ \$s -le \$e ]; do ")
            append("if [ \$s -ne \$l ]; then ")
            append("o=\"\$(( (s>>24) & 255 )).\$(( (s>>16) & 255 )).\$(( (s>>8) & 255 )).\$(( s & 255 ))\"; ")
            append("ping -c 1 -W 1 \"\$o\" >/dev/null 2>&1 & ")
            append("c=\$((c+1)); [ \$((c % ").append(PING_BATCH_SIZE)
            append(")) -eq 0 ] && { wait; echo __FSPLIT_PROG__ \$c; }; ")
            append("fi; s=\$((s+1)); done; wait; ")
            append("echo __FSPLIT_NEIGH__; ")
            append("ip neigh show dev ")
            append(shellQuote(target.interfaceName))
            append(" 2>/dev/null; ")
            append("echo __FSPLIT_ARP__; ")
            append("cat /proc/net/arp 2>/dev/null")
        }
    }

    private fun ipv4ToLong(address: String): Long {
        val octets = address.split('.')
        if (octets.size != 4) {
            return 0L
        }
        return (octets[0].toLong() shl 24) or
            (octets[1].toLong() shl 16) or
            (octets[2].toLong() shl 8) or
            octets[3].toLong()
    }

    private fun parseProbeOutput(
        interfaceName: String,
        output: String,
        knownHosts: Set<String>
    ): Map<String, HostScanResult> {
        val resultsByHost = linkedMapOf<String, HostScanResult>()
        var section = ""

        output.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .forEach { line ->
                when (line) {
                    "__FSPLIT_NEIGH__" -> section = "neigh"
                    "__FSPLIT_ARP__" -> section = "arp"
                    else -> when (section) {
                        "neigh" -> parseNeighborLine(line, knownHosts)?.let { result ->
                            resultsByHost[result.hostAddress] = result
                        }
                        "arp" -> parseArpLine(line, interfaceName, knownHosts)?.let { result ->
                            resultsByHost.putIfAbsent(result.hostAddress, result)
                        }
                    }
                }
            }

        return resultsByHost
    }

    private fun parseNeighborLine(line: String, knownHosts: Set<String>): HostScanResult? {
        val host = IPV4_AT_START.find(line)?.value ?: return null
        if (host !in knownHosts) {
            return null
        }
        if (line.contains("FAILED") || line.contains("INCOMPLETE")) {
            return null
        }

        // `ip neigh` lines look like: "192.168.1.1 lladdr 00:11:22:33:44:55 REACHABLE"
        val mac = LLADDR_REGEX.find(line)?.groupValues?.getOrNull(1)?.let(::normalizeMac)
        return HostScanResult(
            hostAddress = host,
            finding = resourceProvider.getString(R.string.host_result_neighbor),
            macAddress = mac,
            vendor = ouiLookup.vendorFor(mac)
        )
    }

    private fun parseArpLine(
        line: String,
        interfaceName: String,
        knownHosts: Set<String>
    ): HostScanResult? {
        if (line.startsWith("IP address")) {
            return null
        }

        val columns = line.split(WHITESPACE_REGEX)
        if (columns.size < 6) {
            return null
        }

        val host = columns[0]
        val flags = columns[2]
        val mac = columns[3]
        val device = columns[5]
        if (host !in knownHosts || device != interfaceName || flags == "0x0") {
            return null
        }
        if (mac == "00:00:00:00:00:00") {
            return null
        }

        val normalizedMac = normalizeMac(mac)
        return HostScanResult(
            hostAddress = host,
            finding = resourceProvider.getString(R.string.host_result_arp),
            macAddress = normalizedMac,
            vendor = ouiLookup.vendorFor(normalizedMac)
        )
    }

    /** Normalize to lowercase colon-separated form, or null if it isn't a usable MAC. */
    private fun normalizeMac(raw: String?): String? {
        val value = raw?.trim()?.lowercase() ?: return null
        if (!MAC_REGEX.matches(value) || value == "00:00:00:00:00:00") {
            return null
        }
        return value
    }

    private fun probeTcpReachability(host: String): HostScanResult? {
        for (port in TCP_SUPPLEMENT_PORTS) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(host, port), TCP_CONNECT_TIMEOUT_MS)
                    return HostScanResult(
                        hostAddress = host,
                        finding = resourceProvider.getString(R.string.host_result_open_tcp, port)
                    )
                }
            } catch (_: ConnectException) {
                return HostScanResult(
                    hostAddress = host,
                    finding = resourceProvider.getString(R.string.host_result_refused_tcp, port)
                )
            } catch (_: SocketTimeoutException) {
            } catch (_: Exception) {
            }
        }
        return null
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }

    companion object {
        private const val SWEEP_TIMEOUT_BASE_MS = 20_000L
        private const val SWEEP_TIMEOUT_PER_HOST_MS = 15L
        private const val SWEEP_TIMEOUT_MAX_MS = 180_000L
        private const val PING_BATCH_SIZE = 100
        private const val TCP_SUPPLEMENT_MAX_HOSTS = 256
        private const val PROGRESS_MARKER = "__FSPLIT_PROG__"
        private const val NEIGH_MARKER = "__FSPLIT_NEIGH__"
        private const val TCP_CONNECT_TIMEOUT_MS = 160
        private const val TCP_PROBE_PARALLELISM = 24
        private val TCP_SUPPLEMENT_PORTS = intArrayOf(445, 139, 80, 443, 22, 53, 8080, 5555)
        private val IPV4_AT_START = Regex("""^\d{1,3}(?:\.\d{1,3}){3}""")
        private val WHITESPACE_REGEX = Regex("""\s+""")
        private val LLADDR_REGEX = Regex("""lladdr\s+([0-9a-fA-F:]{17})""")
        private val MAC_REGEX = Regex("""^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$""")
    }
}
