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
import org.fsploit.android.domain.model.PortScanReport
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.domain.model.PortState
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

class PortScanRepository(
    private val resourceProvider: ResourceProvider
) {
    suspend fun scan(
        hostAddress: String,
        config: PortScanConfig
    ): PortScanReport = coroutineScope {
        val ports = parsePortSpec(config.portSpec)
        val semaphore = Semaphore(config.parallelism.coerceIn(1, 64))
        val results = ports.map { port ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    scanPort(hostAddress, port, config.connectTimeoutMs)
                }
            }
        }.awaitAll().sortedBy { it.port }

        val openPorts = results.filter { it.state == PortState.OPEN }
        val summary = if (openPorts.isEmpty()) {
            resourceProvider.getString(R.string.port_scan_no_open, hostAddress, ports.size)
        } else {
            resourceProvider.getString(
                R.string.port_scan_found_open,
                openPorts.size,
                hostAddress,
                ports.size
            )
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
}
