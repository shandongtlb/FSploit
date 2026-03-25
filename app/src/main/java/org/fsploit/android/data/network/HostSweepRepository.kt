package org.fsploit.android.data.network

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.HostScanResult
import org.fsploit.android.domain.model.HostSweepReport
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

class HostSweepRepository(
    private val networkInterfaceRepository: NetworkInterfaceRepository,
    private val resourceProvider: ResourceProvider
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

        val semaphore = Semaphore(24)
        val responsiveHosts = target.hostCandidates.map { host ->
            async(Dispatchers.IO) {
                semaphore.withPermit {
                    probeHost(host)
                }
            }
        }.awaitAll().filterNotNull()

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

    private fun probeHost(host: String): HostScanResult? {
        val ports = intArrayOf(22, 53, 80, 443, 8080, 5555)
        for (port in ports) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress(host, port), 180)
                    return HostScanResult(
                        host,
                        resourceProvider.getString(R.string.host_result_open_tcp, port)
                    )
                }
            } catch (exception: ConnectException) {
                return HostScanResult(
                    host,
                    resourceProvider.getString(R.string.host_result_refused_tcp, port)
                )
            } catch (_: SocketTimeoutException) {
            } catch (_: Exception) {
            }
        }

        return try {
            val address = InetAddress.getByName(host)
            if (address.isReachable(250)) {
                HostScanResult(host, resourceProvider.getString(R.string.host_result_icmp))
            } else {
                null
            }
        } catch (_: Exception) {
            null
        }
    }
}
