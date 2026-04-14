package org.fsploit.android.data.mitm

import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.MitmToolchainConfig
import java.io.File

class MitmRuntimeController(
    private val shellRepository: ShellRepository
) {
    fun startBettercapCaplet(
        config: MitmToolchainConfig,
        name: String,
        interfaceName: String,
        sessionDirectory: File,
        logFile: File,
        capletContent: String
    ): Long? {
        val capletFile = File(sessionDirectory, "$name.cap")
        capletFile.writeText(capletContent)
        val scriptBody = buildBettercapScript(config, interfaceName, capletFile)
        if (scriptBody.isBlank()) {
            return null
        }
        return startDetachedProcess(
            name = name,
            sessionDirectory = sessionDirectory,
            logFile = logFile,
            body = scriptBody
        )
    }

    fun startDetachedProcess(
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

    fun terminateProcess(pid: Long) {
        shellRepository.execute(
            command = "kill -15 $pid 2>/dev/null || true; sleep 1; kill -0 $pid 2>/dev/null && kill -9 $pid 2>/dev/null || true",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
    }

    fun applyPortRedirect(port: Int) {
        shellRepository.execute(
            command = "iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports $port 2>/dev/null || iptables -t nat -I PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports $port",
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )
    }

    fun clearPortRedirect(port: Int) {
        shellRepository.execute(
            command = "while iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports $port 2>/dev/null; do :; done",
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )
    }

    fun setForwarding(enabled: Boolean) {
        shellRepository.execute(
            command = "echo ${if (enabled) 1 else 0} > /proc/sys/net/ipv4/ip_forward",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
    }

    fun isProcessAlive(pid: Long): Boolean {
        val result = shellRepository.execute(
            command = "kill -0 $pid",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
        return result.exitCode == 0 && !result.timedOut
    }

    fun applyForwardDrop(targetHost: String): Boolean {
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

    fun clearForwardDrop(targetHost: String) {
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

    fun hasForwardDrop(targetHost: String): Boolean {
        val result = shellRepository.execute(
            command = buildString {
                append("iptables -C FORWARD -s ")
                append(targetHost)
                append(" -j DROP >/dev/null 2>&1 && ")
                append("iptables -C FORWARD -d ")
                append(targetHost)
                append(" -j DROP >/dev/null 2>&1")
            },
            asRoot = true,
            timeoutMs = FIREWALL_TIMEOUT_MS
        )
        return result.exitCode == 0 && !result.timedOut
    }

    fun buildTcpdumpScript(
        config: MitmToolchainConfig,
        interfaceName: String,
        targetHost: String,
        artifactPath: String
    ): String {
        return "exec ${shellCommandToken(config.tcpdumpPath)} -i ${shellQuote(interfaceName)} -n -s 0 host ${shellQuote(targetHost)} and not arp -w ${shellQuote(artifactPath)}\n"
    }

    fun buildMitmdumpScript(
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

    private fun buildBettercapScript(
        config: MitmToolchainConfig,
        interfaceName: String,
        capletFile: File
    ): String {
        val bettercapPath = config.bettercapPath.trim()
        if (bettercapPath.contains('/')) {
            val sourceBinary = File(bettercapPath)
            val sourceDirectory = sourceBinary.parentFile ?: return ""
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
