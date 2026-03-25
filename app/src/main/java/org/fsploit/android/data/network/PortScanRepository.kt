package org.fsploit.android.data.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import org.fsploit.android.domain.model.PortScanReport
import org.fsploit.android.domain.model.PortScanResult
import org.fsploit.android.domain.model.PortState
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

class PortScanRepository {
    suspend fun scanCommonPorts(hostAddress: String): PortScanReport = coroutineScope {
        val targets = listOf(
            21 to "ftp",
            22 to "ssh",
            23 to "telnet",
            53 to "dns",
            80 to "http",
            110 to "pop3",
            139 to "netbios",
            143 to "imap",
            443 to "https",
            445 to "smb",
            3306 to "mysql",
            3389 to "rdp",
            5432 to "postgres",
            5900 to "vnc",
            8080 to "http-alt",
            8443 to "https-alt"
        )

        val results = targets.map { (port, protocol) ->
            async(Dispatchers.IO) {
                scanPort(hostAddress, port, protocol)
            }
        }.awaitAll().sortedBy { it.port }

        val openPorts = results.filter { it.state == PortState.OPEN }
        val summary = if (openPorts.isEmpty()) {
            "No common open TCP ports were found on $hostAddress."
        } else {
            "Found ${openPorts.size} open TCP port(s) on $hostAddress."
        }

        PortScanReport(
            hostAddress = hostAddress,
            scannedPorts = results,
            summary = summary
        )
    }

    private fun scanPort(hostAddress: String, port: Int, protocol: String): PortScanResult {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(hostAddress, port), 250)
                PortScanResult(
                    port = port,
                    protocol = protocol,
                    state = PortState.OPEN,
                    note = "accepted connection"
                )
            }
        } catch (_: ConnectException) {
            PortScanResult(
                port = port,
                protocol = protocol,
                state = PortState.CLOSED,
                note = "actively refused"
            )
        } catch (_: SocketTimeoutException) {
            PortScanResult(
                port = port,
                protocol = protocol,
                state = PortState.FILTERED,
                note = "timed out"
            )
        } catch (exception: Exception) {
            PortScanResult(
                port = port,
                protocol = protocol,
                state = PortState.FILTERED,
                note = exception.javaClass.simpleName
            )
        }
    }
}
