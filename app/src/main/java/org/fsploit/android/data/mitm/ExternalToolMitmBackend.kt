package org.fsploit.android.data.mitm

import android.content.Context
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.ConnectionBlockResult
import org.fsploit.android.domain.model.ConnectionBlockMode
import org.fsploit.android.domain.model.MitmActionResult
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.MitmToolchainConfig
import org.fsploit.android.domain.model.ShellStatus
import java.io.File
import java.net.Inet4Address
import java.net.InetAddress

class ExternalToolMitmBackend(
    context: Context,
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository,
    private val preferencesRepository: AppPreferencesRepository
) : MitmBackend {
    private val sessionStore = MitmSessionStore(context)
    private val blockStore = ConnectionBlockStore(context)
    private val toolchainProbe = ToolchainProbe(resourceProvider, shellRepository, preferencesRepository)
    private val bettercapCapletFactory = BettercapCapletFactory(resourceProvider)
    private val runtimeController = MitmRuntimeController(shellRepository)
    private val sessionLauncher = MitmSessionLauncher(
        resourceProvider = resourceProvider,
        runtimeController = runtimeController,
        bettercapCapletFactory = bettercapCapletFactory,
        mitmdumpAddonFactory = MitmdumpAddonFactory(resourceProvider)
    )

    override fun loadReadiness(shellStatus: ShellStatus): MitmReadiness {
        return toolchainProbe.loadReadiness(shellStatus)
    }

    override fun loadSession(): MitmSession {
        val record = sessionStore.loadRecord()
            ?: return MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
        val active = record.pids.any(runtimeController::isProcessAlive) ||
            (
                record.forwardDropTargetHost.isNotBlank() &&
                    runtimeController.hasForwardDrop(record.forwardDropTargetHost)
                )
        if (!active) {
            sessionStore.clear()
            return MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
        }
        return record.session
    }

    override fun startSession(request: MitmLaunchRequest): MitmActionResult {
        val targetHost = validateIpv4(request.targetHost)
            ?: return MitmActionResult(
                success = false,
                summary = resourceProvider.getString(R.string.block_invalid_host)
            )
        val interfaceName = request.interfaceName.trim()
        if (interfaceName.isEmpty()) {
            return MitmActionResult(
                success = false,
                summary = resourceProvider.getString(R.string.mitm_interface_required)
            )
        }
        val gatewayAddress = if (requiresGateway(request.mode, request.networkMode)) {
            validateIpv4(request.gatewayAddress)
                ?: return MitmActionResult(
                    success = false,
                    summary = resourceProvider.getString(R.string.mitm_gateway_required, interfaceName)
                )
        } else {
            ""
        }

        val readiness = loadReadiness(
            ShellStatus(
                shellAvailable = true,
                suAvailable = true,
                rootGranted = true,
                summary = ""
            )
        )
        val missingToolSummary = missingToolSummary(request.mode, request.networkMode, readiness)
        if (missingToolSummary != null) {
            return MitmActionResult(success = false, summary = missingToolSummary)
        }

        stopSession()

        val config = toolchainProbe.loadConfig()
        val startedAt = System.currentTimeMillis()
        val sessionDirectory = sessionStore.createSessionDirectory(startedAt)
        val mainLogFile = File(sessionDirectory, "bettercap.log")
        val launchArtifacts = try {
            sessionLauncher.launch(
                request = request,
                config = config,
                targetHost = targetHost,
                interfaceName = interfaceName,
                gatewayAddress = gatewayAddress,
                sessionDirectory = sessionDirectory,
                logFile = mainLogFile
            )
        } catch (exception: IllegalArgumentException) {
            cleanupSession(emptyList(), 0, false, "")
            return MitmActionResult(success = false, summary = exception.message.orEmpty())
        } catch (_: Exception) {
            cleanupSession(emptyList(), 0, false, "")
            return MitmActionResult(
                success = false,
                summary = resourceProvider.getString(R.string.mitm_session_start_failed)
            )
        }

        val session = MitmSession(
            active = true,
            mode = request.mode,
            targetHost = targetHost,
            interfaceName = interfaceName,
            summary = resourceProvider.getString(
                R.string.mitm_session_running,
                resourceProvider.getString(request.mode.titleRes),
                targetHost
            ),
            logPath = mainLogFile.absolutePath,
            artifactPath = launchArtifacts.artifactPath,
            startedAtEpochMs = startedAt
        )
        sessionStore.saveRecord(
            ActiveMitmSessionRecord(
                session = session,
                pids = launchArtifacts.pids,
                redirectPort = launchArtifacts.redirectPort,
                forwardingEnabled = launchArtifacts.forwardingEnabled,
                forwardDropTargetHost = launchArtifacts.forwardDropTargetHost
            )
        )

        return MitmActionResult(
            success = true,
            summary = session.summary,
            session = session
        )
    }

    override fun stopSession(): MitmActionResult {
        val record = sessionStore.loadRecord()
            ?: return MitmActionResult(
                success = true,
                summary = resourceProvider.getString(R.string.mitm_session_idle),
                session = MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
            )

        cleanupSession(
            record.pids,
            record.redirectPort,
            record.forwardingEnabled,
            record.forwardDropTargetHost
        )
        sessionStore.clear()

        return MitmActionResult(
            success = true,
            summary = resourceProvider.getString(R.string.mitm_session_stopped),
            session = MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
        )
    }

    override fun blockHost(
        targetHost: String,
        interfaceName: String,
        mode: ConnectionBlockMode
    ): ConnectionBlockResult {
        if (interfaceName.isBlank()) {
            return ConnectionBlockResult(
                targetHost = targetHost,
                success = false,
                summary = resourceProvider.getString(R.string.mitm_interface_required)
            )
        }

        val readiness = loadReadiness(
            ShellStatus(
                shellAvailable = true,
                suAvailable = true,
                rootGranted = true,
                summary = ""
            )
        )
        stopConnectionBlockInternal()
        val startedAt = System.currentTimeMillis()
        val blockDirectory = blockStore.createBlockDirectory(startedAt)
        val logFile = File(blockDirectory, "connection_block.log")
        val record = when (mode) {
            ConnectionBlockMode.NORMAL -> {
                if (!readiness.bettercapAvailable) {
                    return ConnectionBlockResult(
                        targetHost = targetHost,
                        success = false,
                        summary = resourceProvider.getString(R.string.mitm_missing_bettercap)
                    )
                }
                val config = toolchainProbe.loadConfig()
                val pid = runtimeController.startBettercapCaplet(
                    config = config,
                    name = "connection_block",
                    interfaceName = interfaceName,
                    sessionDirectory = blockDirectory,
                    logFile = logFile,
                    capletContent = bettercapCapletFactory.buildArpBanCaplet(targetHost)
                )
                if (pid == null) {
                    return ConnectionBlockResult(
                        targetHost = targetHost,
                        success = false,
                        summary = resourceProvider.getString(R.string.mitm_session_start_failed)
                    )
                }
                ActiveConnectionBlockRecord(
                    targetHost = targetHost,
                    interfaceName = interfaceName,
                    mode = mode,
                    pid = pid,
                    logPath = logFile.absolutePath,
                    startedAtEpochMs = startedAt
                )
            }

            ConnectionBlockMode.HOTSPOT -> {
                if (!readiness.iptablesAvailable) {
                    return ConnectionBlockResult(
                        targetHost = targetHost,
                        success = false,
                        summary = resourceProvider.getString(R.string.mitm_missing_iptables)
                    )
                }
                if (!runtimeController.applyForwardDrop(targetHost)) {
                    return ConnectionBlockResult(
                        targetHost = targetHost,
                        success = false,
                        summary = resourceProvider.getString(R.string.block_failed, targetHost, "iptables FORWARD")
                    )
                }
                logFile.writeText("FORWARD DROP active for $targetHost on $interfaceName\n")
                ActiveConnectionBlockRecord(
                    targetHost = targetHost,
                    interfaceName = interfaceName,
                    mode = mode,
                    pid = null,
                    logPath = logFile.absolutePath,
                    startedAtEpochMs = startedAt
                )
            }
        }

        blockStore.saveRecord(
            record
        )

        return ConnectionBlockResult(
            targetHost = targetHost,
            success = true,
            summary = resourceProvider.getString(R.string.block_applied, targetHost)
        )
    }

    override fun unblockHost(hostAddress: String): ConnectionBlockResult {
        val record = loadConnectionBlockRecord()
            ?: return ConnectionBlockResult(
                targetHost = hostAddress,
                success = true,
                summary = resourceProvider.getString(R.string.block_removed, hostAddress)
            )

        stopConnectionBlockInternal()
        return ConnectionBlockResult(
            targetHost = record.targetHost,
            success = true,
            summary = resourceProvider.getString(R.string.block_removed, record.targetHost)
        )
    }

    private fun cleanupSession(
        pids: List<Long>,
        redirectPort: Int,
        forwardingEnabled: Boolean,
        forwardDropTargetHost: String
    ) {
        pids.forEach { pid ->
            runtimeController.terminateProcess(pid)
        }
        if (redirectPort > 0) {
            runtimeController.clearPortRedirect(redirectPort)
        }
        if (forwardingEnabled) {
            runtimeController.setForwarding(false)
        }
        if (forwardDropTargetHost.isNotBlank()) {
            runtimeController.clearForwardDrop(forwardDropTargetHost)
        }
    }

    private fun loadConnectionBlockRecord(): ActiveConnectionBlockRecord? {
        val record = blockStore.loadRecord() ?: return null
        if (record.mode == ConnectionBlockMode.NORMAL && record.pid != null && !runtimeController.isProcessAlive(record.pid)) {
            blockStore.clear()
            return null
        }
        return record
    }

    private fun stopConnectionBlockInternal() {
        val record = blockStore.loadRecord() ?: return
        when (record.mode) {
            ConnectionBlockMode.NORMAL -> {
                val pid = record.pid
                if (pid != null) {
                    runtimeController.terminateProcess(pid)
                }
            }

            ConnectionBlockMode.HOTSPOT -> runtimeController.clearForwardDrop(record.targetHost)
        }
        blockStore.clear()
    }

    private fun missingToolSummary(
        mode: MitmMode,
        networkMode: ConnectionBlockMode,
        readiness: MitmReadiness
    ): String? {
        return when (mode) {
            MitmMode.CONNECTION_KILL ->
                when (networkMode) {
                    ConnectionBlockMode.NORMAL ->
                        if (!readiness.bettercapAvailable) resourceProvider.getString(R.string.mitm_missing_bettercap) else null
                    ConnectionBlockMode.HOTSPOT ->
                        if (!readiness.iptablesAvailable) resourceProvider.getString(R.string.mitm_missing_iptables) else null
                }

            MitmMode.SNIFFER ->
                when {
                    !readiness.tcpdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_tcpdump)
                    networkMode == ConnectionBlockMode.NORMAL && !readiness.bettercapAvailable ->
                        resourceProvider.getString(R.string.mitm_missing_bettercap)
                    else -> null
                }

            MitmMode.PASSWORD_SNIFFER,
            MitmMode.DNS_SPOOF ->
                if (!readiness.bettercapAvailable) {
                    resourceProvider.getString(R.string.mitm_missing_bettercap)
                } else {
                    null
                }

            MitmMode.REDIRECT,
            MitmMode.IMAGE_REPLACE,
            MitmMode.VIDEO_REPLACE,
            MitmMode.SCRIPT_INJECTION,
            MitmMode.CUSTOM_FILTER,
            MitmMode.SESSION_HIJACK ->
                when {
                    !readiness.iptablesAvailable -> resourceProvider.getString(R.string.mitm_missing_iptables)
                    !readiness.mitmdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_mitmdump)
                    networkMode == ConnectionBlockMode.NORMAL && !readiness.bettercapAvailable ->
                        resourceProvider.getString(R.string.mitm_missing_bettercap)
                    else -> null
                }
        }
    }

    private fun requiresGateway(mode: MitmMode, networkMode: ConnectionBlockMode): Boolean {
        if (networkMode == ConnectionBlockMode.HOTSPOT) {
            return false
        }
        return when (mode) {
            MitmMode.CONNECTION_KILL -> false
            MitmMode.SNIFFER,
            MitmMode.PASSWORD_SNIFFER,
            MitmMode.DNS_SPOOF,
            MitmMode.REDIRECT,
            MitmMode.IMAGE_REPLACE,
            MitmMode.VIDEO_REPLACE,
            MitmMode.SCRIPT_INJECTION,
            MitmMode.CUSTOM_FILTER,
            MitmMode.SESSION_HIJACK -> true
        }
    }

    private fun validateIpv4(hostAddress: String): String? {
        return try {
            val address = InetAddress.getByName(hostAddress.trim())
            if (address is Inet4Address) address.hostAddress else null
        } catch (_: Exception) {
            null
        }
    }
}
