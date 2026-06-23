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

    /** Cheap liveness check used to poll a freshly launched RPC daemon until it answers. */
    fun isReachable(config: MsfRpcConfig): Boolean {
        val client = MsfRpcClient(config)
        return try {
            val version = client.call("core.version")
            version is Map<*, *> && version["version"] != null
        } catch (_: Exception) {
            false
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

    fun writeSession(
        config: MsfRpcConfig,
        sessionId: String,
        sessionType: String,
        data: String
    ): MsfActionResult {
        val method = if (MsfSessionType.isMeterpreter(sessionType)) {
            "session.meterpreter_write"
        } else {
            "session.shell_write"
        }
        // Both transports execute on newline, so append one if the caller did not.
        val payload = if (data.endsWith("\n")) data else "$data\n"
        return runAction {
            val client = MsfRpcClient(config)
            try {
                client.call(method, sessionArg(sessionId), payload)
            } finally {
                client.logout()
            }
            resourceProvider.getString(R.string.msf_console_write_success, sessionId)
        }
    }

    fun readSession(
        config: MsfRpcConfig,
        sessionId: String,
        sessionType: String
    ): MsfConsoleResult {
        val method = if (MsfSessionType.isMeterpreter(sessionType)) {
            "session.meterpreter_read"
        } else {
            "session.shell_read"
        }
        val client = MsfRpcClient(config)
        return try {
            val response = client.call(method, sessionArg(sessionId)) as? Map<*, *>
            MsfConsoleResult(
                success = true,
                data = response?.get("data")?.toString().orEmpty(),
                message = ""
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
}
