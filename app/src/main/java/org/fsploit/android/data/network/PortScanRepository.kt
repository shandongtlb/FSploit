package org.fsploit.android.data.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.PortScanConfig
import org.fsploit.android.domain.model.PortScanMode
import org.fsploit.android.domain.model.PortScanReport
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.domain.model.PortState
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

class PortScanRepository(
    private val resourceProvider: ResourceProvider,
    private val nmapScanner: NmapScanner
) {
    suspend fun scan(
        hostAddress: String,
        config: PortScanConfig,
        mode: PortScanMode = PortScanMode.NORMAL,
        interfaceName: String? = null
    ): PortScanReport = coroutineScope {
        // UDP uses its own curated high-value port set (not the TCP spec) and is nmap-only — a UDP
        // connect-scan over sockets can't tell open from filtered, so there's no useful fallback.
        if (mode == PortScanMode.UDP) {
            return@coroutineScope if (nmapScanner.isAvailable()) {
                nmapScanner.scanPorts(hostAddress, UDP_PORTS, mode, interfaceName)
            } else {
                PortScanReport(
                    hostAddress = hostAddress,
                    requestedPorts = UDP_PORTS,
                    scannedPorts = emptyList(),
                    summary = resourceProvider.getString(R.string.port_scan_udp_requires_nmap)
                )
            }
        }

        val ports = parsePortSpec(config.portSpec)

        // Prefer nmap (service/version/OS) when the managed package is present; otherwise fall back
        // to the builtin socket connect-scan so port scanning always works.
        if (nmapScanner.isAvailable()) {
            val report = nmapScanner.scanPorts(
                hostAddress = hostAddress,
                ports = ports,
                mode = mode,
                interfaceName = interfaceName
            )
            return@coroutineScope report
        }

        val semaphore = Semaphore(config.parallelism.coerceIn(1, 64))
        val results = ports.map { port ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    scanPort(hostAddress, port, config.connectTimeoutMs)
                }
            }
        }.awaitAll().sortedBy { it.port }

        val openPorts = results.filter { it.state == PortState.OPEN }
        val baseSummary = if (openPorts.isEmpty()) {
            resourceProvider.getString(R.string.port_scan_no_open, hostAddress, ports.size)
        } else {
            resourceProvider.getString(
                R.string.port_scan_found_open,
                openPorts.size,
                hostAddress,
                ports.size
            )
        }
        // The advanced profile is nmap-only; note the downgrade so results aren't misread.
        val summary = if (mode == PortScanMode.ADVANCED) {
            baseSummary + " " + resourceProvider.getString(R.string.port_scan_nmap_fallback)
        } else {
            baseSummary
        }

        PortScanReport(
            hostAddress = hostAddress,
            requestedPorts = ports,
            scannedPorts = results,
            summary = summary
        )
    }

    private fun scanPort(
        hostAddress: String,
        port: Int,
        connectTimeoutMs: Int
    ): PortScanResult {
        val protocol = protocolForPort(port)
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(hostAddress, port), connectTimeoutMs)
                PortScanResult(
                    port = port,
                    protocol = protocol,
                    state = PortState.OPEN,
                    note = resourceProvider.getString(R.string.port_note_accepted_connection)
                )
            }
        } catch (_: ConnectException) {
            PortScanResult(
                port = port,
                protocol = protocol,
                state = PortState.CLOSED,
                note = resourceProvider.getString(R.string.port_note_actively_refused)
            )
        } catch (_: SocketTimeoutException) {
            PortScanResult(
                port = port,
                protocol = protocol,
                state = PortState.FILTERED,
                note = resourceProvider.getString(R.string.port_note_timed_out)
            )
        } catch (exception: Exception) {
            PortScanResult(
                port = port,
                protocol = protocol,
                state = PortState.FILTERED,
                note = resourceProvider.getString(
                    R.string.port_note_exception,
                    exception.javaClass.simpleName
                )
            )
        }
    }

    private fun parsePortSpec(portSpec: String): List<Int> {
        val result = linkedSetOf<Int>()
        val tokens = portSpec.split(',').map { it.trim() }.filter { it.isNotEmpty() }
        if (tokens.isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.port_spec_empty))
        }

        tokens.forEach { token ->
            val rangeParts = token.split('-').map { it.trim() }
            when (rangeParts.size) {
                1 -> result += parsePort(rangeParts[0], token)
                2 -> {
                    val start = parsePort(rangeParts[0], token)
                    val end = parsePort(rangeParts[1], token)
                    if (end < start) {
                        throw IllegalArgumentException(
                            resourceProvider.getString(R.string.port_spec_range_invalid, token)
                        )
                    }
                    if (end - start > 512) {
                        throw IllegalArgumentException(
                            resourceProvider.getString(R.string.port_spec_range_too_large, token)
                        )
                    }
                    (start..end).forEach { result += it }
                }

                else -> throw IllegalArgumentException(
                    resourceProvider.getString(R.string.port_spec_token_invalid, token)
                )
            }
        }

        if (result.isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.port_spec_empty))
        }

        if (result.size > 256) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.port_spec_too_many))
        }

        return result.toList().sorted()
    }

    private fun parsePort(value: String, token: String): Int {
        val port = value.toIntOrNull()
            ?: throw IllegalArgumentException(
                resourceProvider.getString(R.string.port_spec_token_invalid, token)
            )
        if (port !in 1..65535) {
            throw IllegalArgumentException(
                resourceProvider.getString(R.string.port_spec_port_out_of_range, port)
            )
        }
        return port
    }

    private fun protocolForPort(port: Int): String {
        return when (port) {
            21 -> "ftp"
            22 -> "ssh"
            23 -> "telnet"
            53 -> "dns"
            80 -> "http"
            110 -> "pop3"
            139 -> "netbios"
            143 -> "imap"
            443 -> "https"
            445 -> "smb"
            3306 -> "mysql"
            3389 -> "rdp"
            5432 -> "postgres"
            5900 -> "vnc"
            8080 -> "http-alt"
            8443 -> "https-alt"
            else -> "tcp"
        }
    }

    companion object {
        // Curated high-value UDP ports — keeps the (inherently slow) UDP scan fast while still
        // catching the services that matter on a LAN: DNS, DHCP, TFTP, NTP, NetBIOS, SNMP, IKE/VPN,
        // syslog, RIP, MS-SQL browser, SSDP/UPnP, SIP, mDNS.
        private val UDP_PORTS = listOf(
            53, 67, 69, 123, 137, 138, 161, 162, 500, 514, 520, 1434, 1900, 5060, 5353
        )
    }
}
