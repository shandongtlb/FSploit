package org.fsploit.android.data.network

import kotlinx.coroutines.coroutineScope
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.HostScanResult
import org.fsploit.android.domain.model.HostSweepReport

class HostSweepRepository(
    private val networkInterfaceRepository: NetworkInterfaceRepository,
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository
) {
    suspend fun runSweep(preferredInterfaceName: String): HostSweepReport = coroutineScope {
        val target = networkInterfaceRepository.resolveSweepTarget(preferredInterfaceName)
            ?: return@coroutineScope HostSweepReport(
                interfaceName = "",
                subnetLabel = "",
                scannedHosts = 0,
                responsiveHosts = emptyList(),
                summary = resourceProvider.getString(R.string.host_sweep_unavailable)
            )

        val responsiveHosts = probeHosts(target.interfaceName, target.hostCandidates)

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

    private fun probeHosts(
        interfaceName: String,
        hosts: List<String>
    ): List<HostScanResult> {
        if (hosts.isEmpty()) {
            return emptyList()
        }

        val shellResult = shellRepository.execute(
            command = buildProbeCommand(interfaceName, hosts),
            asRoot = true,
            timeoutMs = HOST_SWEEP_TIMEOUT_MS
        )

        return parseProbeOutput(
            interfaceName = interfaceName,
            output = shellResult.output,
            knownHosts = hosts.toSet()
        )
    }

    private fun buildProbeCommand(interfaceName: String, hosts: List<String>): String {
        return buildString {
            append("PATH=/system/bin:/system/xbin:\$PATH; ")
            hosts.chunked(PING_BATCH_SIZE).forEach { batch ->
                batch.forEach { host ->
                    append("(ping -c 1 -W 1 ")
                    append(shellQuote(host))
                    append(" >/dev/null 2>&1) & ")
                }
                append("wait; ")
            }
            append("echo __FSPLIT_NEIGH__; ")
            append("ip neigh show dev ")
            append(shellQuote(interfaceName))
            append(" 2>/dev/null; ")
            append("echo __FSPLIT_ARP__; ")
            append("cat /proc/net/arp 2>/dev/null")
        }
    }

    private fun parseProbeOutput(
        interfaceName: String,
        output: String,
        knownHosts: Set<String>
    ): List<HostScanResult> {
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

        return resultsByHost.values.sortedBy { it.hostAddress }
    }

    private fun parseNeighborLine(line: String, knownHosts: Set<String>): HostScanResult? {
        val host = IPV4_AT_START.find(line)?.value ?: return null
        if (host !in knownHosts) {
            return null
        }
        if (line.contains("FAILED") || line.contains("INCOMPLETE")) {
            return null
        }

        return HostScanResult(
            hostAddress = host,
            finding = resourceProvider.getString(R.string.host_result_neighbor)
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

        return HostScanResult(
            hostAddress = host,
            finding = resourceProvider.getString(R.string.host_result_arp)
        )
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }

    companion object {
        private const val HOST_SWEEP_TIMEOUT_MS = 45_000L
        private const val PING_BATCH_SIZE = 24
        private val IPV4_AT_START = Regex("""^\d{1,3}(?:\.\d{1,3}){3}""")
        private val WHITESPACE_REGEX = Regex("""\s+""")
    }
}
