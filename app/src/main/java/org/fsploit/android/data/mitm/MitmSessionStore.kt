package org.fsploit.android.data.mitm

import android.content.Context
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmSession
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Properties

class MitmSessionStore(
    context: Context
) {
    private val mitmRootDirectory = File(context.applicationContext.filesDir, "mitm").apply { mkdirs() }
    private val sessionFile = File(mitmRootDirectory, SESSION_FILE_NAME)

    fun createSessionDirectory(startedAtEpochMs: Long): File {
        return File(mitmRootDirectory, "session-$startedAtEpochMs").apply { mkdirs() }
    }

    fun loadRecord(): ActiveMitmSessionRecord? {
        if (!sessionFile.exists()) {
            return null
        }
        val properties = Properties().apply {
            FileInputStream(sessionFile).use { stream -> load(stream) }
        }
        val session = MitmSession(
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
        return ActiveMitmSessionRecord(
            session = session,
            pids = properties.getProperty(KEY_PIDS)
                .orEmpty()
                .split(',')
                .mapNotNull { it.trim().toLongOrNull() },
            redirectPort = properties.getProperty(KEY_REDIRECT_PORT)?.toIntOrNull() ?: 0,
            forwardingEnabled = properties.getProperty(KEY_FORWARDING_ENABLED)?.toBoolean() == true,
            previousForwardingEnabled = properties.getProperty(KEY_PREVIOUS_FORWARDING_ENABLED)
                ?.toBooleanStrictOrNull(),
            forwardDropTargetHost = properties.getProperty(KEY_FORWARD_DROP_TARGET).orEmpty(),
            victimForwardingTargetHost = properties.getProperty(KEY_VICTIM_FORWARDING_TARGET).orEmpty(),
            victimForwardingInterface = properties.getProperty(KEY_VICTIM_FORWARDING_INTERFACE).orEmpty()
        )
    }

    fun saveRecord(record: ActiveMitmSessionRecord) {
        val properties = Properties().apply {
            setProperty(KEY_MODE, record.session.mode?.name.orEmpty())
            setProperty(KEY_TARGET_HOST, record.session.targetHost)
            setProperty(KEY_INTERFACE, record.session.interfaceName)
            setProperty(KEY_SUMMARY, record.session.summary)
            setProperty(KEY_LOG_PATH, record.session.logPath)
            setProperty(KEY_ARTIFACT_PATH, record.session.artifactPath)
            setProperty(KEY_STARTED_AT, record.session.startedAtEpochMs.toString())
            setProperty(KEY_PIDS, record.pids.joinToString(","))
            setProperty(KEY_REDIRECT_PORT, record.redirectPort.toString())
            setProperty(KEY_FORWARDING_ENABLED, record.forwardingEnabled.toString())
            record.previousForwardingEnabled?.let {
                setProperty(KEY_PREVIOUS_FORWARDING_ENABLED, it.toString())
            }
            setProperty(KEY_FORWARD_DROP_TARGET, record.forwardDropTargetHost)
            setProperty(KEY_VICTIM_FORWARDING_TARGET, record.victimForwardingTargetHost)
            setProperty(KEY_VICTIM_FORWARDING_INTERFACE, record.victimForwardingInterface)
        }
        FileOutputStream(sessionFile).use { stream ->
            properties.store(stream, "FSploit MITM session")
        }
    }

    fun clear() {
        sessionFile.delete()
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
        private const val KEY_PREVIOUS_FORWARDING_ENABLED = "previous_forwarding_enabled"
        private const val KEY_FORWARD_DROP_TARGET = "forward_drop_target"
        private const val KEY_VICTIM_FORWARDING_TARGET = "victim_forwarding_target"
        private const val KEY_VICTIM_FORWARDING_INTERFACE = "victim_forwarding_interface"
    }
}
