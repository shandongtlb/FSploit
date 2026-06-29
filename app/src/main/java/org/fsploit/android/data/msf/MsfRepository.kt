package org.fsploit.android.data.msf

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.MsfActionResult
import org.fsploit.android.domain.model.MsfConsoleResult
import org.fsploit.android.domain.model.MsfJobInfo
import org.fsploit.android.domain.model.MsfRpcConfig
import org.fsploit.android.domain.model.MsfRpcOverview
import org.fsploit.android.domain.model.MsfSessionInfo

class MsfRepository(
    private val resourceProvider: ResourceProvider
) {
    fun loadOverview(config: MsfRpcConfig): MsfRpcOverview {
        val client = MsfRpcClient(config)
        return try {
            val version = client.call("core.version") as? Map<*, *> ?: emptyMap<String, Any?>()
            val sessions = parseSessions(client.call("session.list"))
            val jobs = parseJobs(client.call("job.list"))
            MsfRpcOverview(
                connected = true,
                frameworkVersion = version["version"]?.toString().orEmpty(),
                rubyVersion = version["ruby"]?.toString().orEmpty(),
                apiVersion = version["api"]?.toString().orEmpty(),
                sessions = sessions,
                jobs = jobs,
                summary = resourceProvider.getString(
                    R.string.msf_probe_success,
                    version["version"]?.toString().orEmpty().ifBlank { "unknown" },
                    sessions.size,
                    jobs.size
                )
            )
        } catch (exception: Exception) {
            MsfRpcOverview(
                connected = false,
                frameworkVersion = "",
                rubyVersion = "",
                apiVersion = "",
                sessions = emptyList(),
                jobs = emptyList(),
                summary = resourceProvider.getString(
                    R.string.msf_probe_failed,
                    exception.message ?: exception.javaClass.simpleName
                )
            )
        } finally {
            client.logout()
        }
    }

    fun stopSession(config: MsfRpcConfig, sessionId: String): MsfActionResult {
        return runAction {
            val client = MsfRpcClient(config)
            try {
                client.call("session.stop", sessionArg(sessionId))
            } finally {
                client.logout()
            }
            resourceProvider.getString(R.string.msf_session_stop_success, sessionId)
        }
    }

    fun stopJob(config: MsfRpcConfig, jobId: String): MsfActionResult {
        return runAction {
            val client = MsfRpcClient(config)
            try {
                client.call("job.stop", sessionArg(jobId))
            } finally {
                client.logout()
            }
            resourceProvider.getString(R.string.msf_job_stop_success, jobId)
        }
    }

    /**
     * Runs an auxiliary scanner module inside the shared msgrpc instance through a throwaway RPC
     * console (`use <module>; set RHOSTS; run`) and returns its captured output. We use a console
     * rather than `module.execute` because, with no database, scanner findings only exist as printed
     * output — a console is the one place that output is readable back. Any session/job the run
     * spawns still lands in the shared instance, so the terminal sees it too.
     */
    fun runScan(config: MsfRpcConfig, modulePath: String, rhosts: String): MsfConsoleResult {
        // The module path and RHOSTS are interpolated into a console.write payload where '\n'
        // separates msfconsole commands. Reject any embedded newline/carriage-return so a crafted
        // value can't smuggle extra commands into the shared instance.
        if (modulePath.any { it == '\n' || it == '\r' } || rhosts.any { it == '\n' || it == '\r' }) {
            return MsfConsoleResult(
                success = false,
                data = "",
                message = resourceProvider.getString(
                    R.string.msf_action_failed,
                    "invalid module/RHOSTS input"
                )
            )
        }
        val client = MsfRpcClient(config)
        return try {
            val created = client.call("console.create") as? Map<*, *>
                ?: throw IllegalStateException("console.create returned no console")
            val consoleId = created["id"]?.toString()
                ?: throw IllegalStateException("console.create returned no id")

            client.call("console.write", consoleId, "use $modulePath\nset RHOSTS $rhosts\nrun\n")

            val output = StringBuilder()
            // Let the module start, then drain the console until it stops being busy.
            Thread.sleep(SCAN_INITIAL_DELAY_MS)
            var idleReads = 0
            for (attempt in 0 until SCAN_READ_ATTEMPTS) {
                val read = client.call("console.read", consoleId) as? Map<*, *> ?: break
                output.append(read["data"]?.toString().orEmpty())
                if (read["busy"] == true) {
                    idleReads = 0
                } else if (++idleReads >= 2) {
                    // Two consecutive non-busy reads ⇒ the run has settled.
                    break
                }
                Thread.sleep(SCAN_READ_INTERVAL_MS)
            }
            runCatching { client.call("console.destroy", consoleId) }

            MsfConsoleResult(
                success = true,
                data = output.toString().trim(),
                message = resourceProvider.getString(R.string.msf_scan_done, modulePath)
            )
        } catch (exception: Exception) {
            MsfConsoleResult(
                success = false,
                data = "",
                message = resourceProvider.getString(
                    R.string.msf_action_failed,
                    exception.message ?: exception.javaClass.simpleName
                )
            )
        } finally {
            client.logout()
        }
    }

    /**
     * Sets the global RHOSTS/RHOST datastore on the shared msgrpc instance. Because the operator's
     * interactive console and this RPC client are the same framework instance, a later `use <module>`
     * in the terminal inherits the target with no manual re-typing.
     */
    fun pushTarget(config: MsfRpcConfig, host: String): MsfActionResult {
        return runAction {
            val client = MsfRpcClient(config)
            try {
                client.call("core.setg", "RHOSTS", host)
                client.call("core.setg", "RHOST", host)
            } finally {
                client.logout()
            }
            resourceProvider.getString(R.string.msf_push_target_success, host)
        }
    }

    fun startHandler(
        config: MsfRpcConfig,
        payload: String,
        lhost: String,
        lport: String
    ): MsfActionResult {
        val options = MsfModuleCommand.buildHandlerOptions(payload, lhost, lport)
        return executeModule(config, "exploit", "multi/handler", options)
    }

    /** Generic `module.execute`; surfaces the resulting job id (sessions appear asynchronously). */
    private fun executeModule(
        config: MsfRpcConfig,
        moduleType: String,
        moduleName: String,
        options: Map<String, Any>
    ): MsfActionResult {
        return runAction {
            val client = MsfRpcClient(config)
            val response = try {
                client.call("module.execute", moduleType, moduleName, options) as? Map<*, *>
            } finally {
                client.logout()
            }
            val jobId = response?.get("job_id")?.toString().orEmpty().ifBlank { "-" }
            resourceProvider.getString(R.string.msf_module_exec_success, moduleName, jobId)
        }
    }

    private inline fun runAction(block: () -> String): MsfActionResult {
        return try {
            MsfActionResult(success = true, message = block())
        } catch (exception: Exception) {
            MsfActionResult(
                success = false,
                message = resourceProvider.getString(
                    R.string.msf_action_failed,
                    exception.message ?: exception.javaClass.simpleName
                )
            )
        }
    }

    /** MSF expects numeric session/job ids; fall back to the raw string if it is not numeric. */
    private fun sessionArg(id: String): Any = id.trim().toIntOrNull() ?: id.trim()

    private fun parseSessions(raw: Any?): List<MsfSessionInfo> {
        val sessions = raw as? Map<*, *> ?: return emptyList()
        return sessions.entries.map { entry ->
            val id = entry.key.toString()
            val sessionMap = entry.value as? Map<*, *> ?: emptyMap<String, Any?>()
            MsfSessionInfo(
                id = id,
                type = sessionMap["type"]?.toString().orEmpty(),
                tunnelPeer = sessionMap["tunnel_peer"]?.toString().orEmpty(),
                targetHost = sessionMap["target_host"]?.toString().orEmpty(),
                viaExploit = sessionMap["via_exploit"]?.toString().orEmpty(),
                description = sessionMap["desc"]?.toString().orEmpty()
            )
        }.sortedBy { it.id.toIntOrNull() ?: Int.MAX_VALUE }
    }

    private fun parseJobs(raw: Any?): List<MsfJobInfo> {
        val jobs = raw as? Map<*, *> ?: return emptyList()
        return jobs.entries.map { entry ->
            MsfJobInfo(
                id = entry.key.toString(),
                name = entry.value?.toString().orEmpty(),
                description = "${entry.key}: ${entry.value}"
            )
        }.sortedBy { it.id.toIntOrNull() ?: Int.MAX_VALUE }
    }

    private companion object {
        private const val SCAN_INITIAL_DELAY_MS = 1_200L
        private const val SCAN_READ_ATTEMPTS = 40
        private const val SCAN_READ_INTERVAL_MS = 700L
    }
}
