package org.fsploit.android.data.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.mitm.NmapPackageManager
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.HostScanResult
import org.fsploit.android.domain.model.PortScanMode
import org.fsploit.android.domain.model.PortScanReport
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.domain.model.PortState
import org.fsploit.android.domain.model.SweepTarget

/**
 * nmap-backed scan engine. Drives the managed native nmap package (see [NmapPackageManager]) for
 * advanced host discovery and for service/version/OS port scanning, parsing `-oX -` output via
 * [NmapXmlParser]. All callers are expected to fall back to the builtin engines when
 * [isAvailable] is false.
 */
class NmapScanner(
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository,
    private val preferencesRepository: AppPreferencesRepository,
    private val nmapPackageManager: NmapPackageManager
) {
    /** Shell probe of the configured nmap path (covers both the managed package and a custom path). */
    fun isAvailable(): Boolean {
        val path = nmapPath()
        if (path.isEmpty()) {
            return false
        }
        val command = if (path.contains('/')) {
            "[ -x ${shellQuote(path)} ] && echo ok"
        } else {
            "command -v ${shellQuote(path)}"
        }
        val result = shellRepository.execute(command = command, asRoot = true, timeoutMs = PROBE_TIMEOUT_MS)
        return result.exitCode == 0 && result.output.isNotBlank()
    }

    suspend fun discoverHosts(
        target: SweepTarget,
        onProgress: (scanned: Int, total: Int) -> Unit = { _, _ -> }
    ): List<HostScanResult> = withContext(Dispatchers.IO) {
        val subnet = "${target.networkAddress}/${target.prefixLength}"
        // Host discovery only (no port/OS scan) — fast (seconds for a /24), still richer than the
        // builtin sweep: nmap's own ARP scan + vendor DB, and it catches hosts the ping sweep misses.
        // OS/system info is intentionally left to the per-host advanced port scan (-A), so the whole
        // subnet isn't paying the OS-fingerprint cost.
        // `--stats-every` makes nmap emit periodic <taskprogress percent="…"/> elements into the
        // -oX - stream so the UI keeps a live progress readout (the builtin sweep reports per ping
        // batch; without this the nmap path would sit on a frozen "scanning…" line until it finished).
        val command = buildString {
            append(commandPrefix())
            append(" -sn -n --max-retries 2 --stats-every ").append(STATS_INTERVAL)
            if (target.interfaceName.isNotBlank()) {
                append(" -e ").append(shellQuote(target.interfaceName))
            }
            append(" -oX - ").append(shellQuote(subnet))
        }

        val total = target.hostCandidates.size
        val output = shellRepository.execute(
            command = command,
            asRoot = true,
            timeoutMs = discoveryTimeoutMs(total),
            onLine = if (total <= 0) null else { line ->
                val percent = TASK_PROGRESS_PERCENT.find(line)?.groupValues?.getOrNull(1)?.toDoubleOrNull()
                if (percent != null) {
                    val scanned = (percent / 100.0 * total).toInt().coerceIn(0, total)
                    onProgress(scanned, total)
                }
            }
        ).output

        NmapXmlParser.parse(output)
            .filter { it.isUp && !it.ipv4.isNullOrBlank() }
            .map { host ->
                HostScanResult(
                    hostAddress = host.ipv4!!,
                    finding = resourceProvider.getString(R.string.host_result_nmap),
                    macAddress = host.mac?.lowercase(),
                    vendor = host.vendor,
                    osInfo = osLabel(host.osMatches.firstOrNull()?.name, host.osMatches.firstOrNull()?.accuracy)
                )
            }
            .sortedBy { it.hostAddress }
    }

    suspend fun scanPorts(
        hostAddress: String,
        ports: List<Int>,
        mode: PortScanMode,
        interfaceName: String?
    ): PortScanReport = withContext(Dispatchers.IO) {
        val portSpec = ports.joinToString(",")
        val command = buildString {
            append(commandPrefix())
            when (mode) {
                PortScanMode.NORMAL -> append(" -sS -sV")
                PortScanMode.ADVANCED -> append(" -A")
                PortScanMode.UDP -> append(" -sU -sV")
            }
            append(" -n -Pn -T4")
            if (!interfaceName.isNullOrBlank()) {
                append(" -e ").append(shellQuote(interfaceName))
            }
            append(" -p ").append(shellQuote(portSpec))
            append(" -oX - ").append(shellQuote(hostAddress))
        }

        val output = shellRepository.execute(
            command = command,
            asRoot = true,
            timeoutMs = portScanTimeoutMs(ports.size, mode)
        ).output

        val host = NmapXmlParser.parse(output).firstOrNull { !it.ipv4.isNullOrBlank() }
            ?: NmapXmlParser.parse(output).firstOrNull()

        val results = host?.ports.orEmpty().map { port ->
            PortScanResult(
                port = port.portId,
                protocol = port.service?.takeIf { it.isNotBlank() } ?: port.protocol.ifBlank { "tcp" },
                state = portState(port.state),
                note = buildNote(port),
                service = port.service,
                product = port.product,
                version = port.version
            )
        }.sortedBy { it.port }

        val openPorts = results.count { it.state == PortState.OPEN }
        val summary = if (openPorts == 0) {
            resourceProvider.getString(R.string.port_scan_no_open, hostAddress, ports.size)
        } else {
            resourceProvider.getString(R.string.port_scan_found_open, openPorts, hostAddress, ports.size)
        }

        PortScanReport(
            hostAddress = hostAddress,
            requestedPorts = ports,
            scannedPorts = results,
            summary = summary,
            osInfo = host?.osMatches?.firstOrNull()?.let { osLabel(it.name, it.accuracy) },
            hostnames = host?.hostnames.orEmpty()
        )
    }

    private fun buildNote(port: NmapPort): String {
        val detail = listOfNotNull(
            port.product?.takeIf { it.isNotBlank() },
            port.version?.takeIf { it.isNotBlank() },
            port.extraInfo?.takeIf { it.isNotBlank() }?.let { "($it)" }
        ).joinToString(" ")
        return detail.ifBlank { port.service ?: port.state }
    }

    private fun osLabel(name: String?, accuracy: Int?): String? {
        if (name.isNullOrBlank()) {
            return null
        }
        return if (accuracy != null && accuracy > 0) {
            resourceProvider.getString(R.string.nmap_os_label, name, accuracy)
        } else {
            name
        }
    }

    private fun portState(state: String): PortState = when (state) {
        "open" -> PortState.OPEN
        "closed" -> PortState.CLOSED
        else -> PortState.FILTERED
    }

    /** `LD_LIBRARY_PATH=… <nmap> --datadir …` when the managed package is installed; bare path otherwise. */
    private fun commandPrefix(): String {
        val path = nmapPath()
        return if (nmapPackageManager.isManagedPackageInstalled()) {
            val dir = nmapPackageManager.installRootPath
            "LD_LIBRARY_PATH=${shellQuote(dir)}:\$LD_LIBRARY_PATH ${shellQuote(path)} --datadir ${shellQuote(dir)}"
        } else {
            shellQuote(path)
        }
    }

    private fun nmapPath(): String = preferencesRepository.getMitmToolchainConfig().nmapPath.trim()

    private fun discoveryTimeoutMs(hostCount: Int): Long {
        return (DISCOVERY_TIMEOUT_BASE_MS + hostCount.toLong() * DISCOVERY_TIMEOUT_PER_HOST_MS)
            .coerceAtMost(DISCOVERY_TIMEOUT_MAX_MS)
    }

    private fun portScanTimeoutMs(portCount: Int, mode: PortScanMode): Long {
        val base = when (mode) {
            PortScanMode.NORMAL -> NORMAL_PORT_TIMEOUT_BASE_MS
            PortScanMode.ADVANCED -> ADVANCED_PORT_TIMEOUT_BASE_MS
            PortScanMode.UDP -> UDP_PORT_TIMEOUT_BASE_MS
        }
        // UDP is far slower per port (silent drops + ICMP rate-limiting force retransmits/timeouts).
        val perPort = if (mode == PortScanMode.UDP) UDP_PORT_TIMEOUT_PER_PORT_MS else PORT_TIMEOUT_PER_PORT_MS
        return (base + portCount.toLong() * perPort).coerceAtMost(PORT_TIMEOUT_MAX_MS)
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }

    companion object {
        // How often nmap reports scan progress; short so a fast /24 still emits a few updates.
        private const val STATS_INTERVAL = "1s"
        private val TASK_PROGRESS_PERCENT = Regex("""<taskprogress[^>]*\spercent="([0-9.]+)"""")
        private const val PROBE_TIMEOUT_MS = 2000L
        // `-sn` host discovery is seconds-fast even on a /24; keep a modest, host-count-scaled budget.
        private const val DISCOVERY_TIMEOUT_BASE_MS = 30_000L
        private const val DISCOVERY_TIMEOUT_PER_HOST_MS = 300L
        private const val DISCOVERY_TIMEOUT_MAX_MS = 120_000L
        private const val NORMAL_PORT_TIMEOUT_BASE_MS = 60_000L
        private const val ADVANCED_PORT_TIMEOUT_BASE_MS = 180_000L
        private const val UDP_PORT_TIMEOUT_BASE_MS = 120_000L
        private const val PORT_TIMEOUT_PER_PORT_MS = 400L
        private const val UDP_PORT_TIMEOUT_PER_PORT_MS = 3_000L
        private const val PORT_TIMEOUT_MAX_MS = 420_000L
    }
}
