package org.fsploit.android.data.msf

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.MsfJobInfo
import org.fsploit.android.domain.model.MsfRpcConfig
import org.fsploit.android.domain.model.MsfRpcOverview
import org.fsploit.android.domain.model.MsfSessionInfo

class MsfRepository(
    private val resourceProvider: ResourceProvider
) {
    fun loadOverview(config: MsfRpcConfig): MsfRpcOverview {
        return try {
            val client = MsfRpcClient(config)
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
        }
    }

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
