package org.fsploit.android.data.mitm

import android.content.Context
import org.fsploit.android.domain.model.ConnectionBlockMode
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.Properties

class ConnectionBlockStore(
    context: Context
) {
    private val mitmRootDirectory = File(context.applicationContext.filesDir, "mitm").apply { mkdirs() }
    private val recordFile = File(mitmRootDirectory, RECORD_FILE_NAME)

    fun createBlockDirectory(startedAtEpochMs: Long): File {
        return File(mitmRootDirectory, "block-$startedAtEpochMs").apply { mkdirs() }
    }

    fun loadRecord(): ActiveConnectionBlockRecord? {
        if (!recordFile.exists()) {
            return null
        }
        val properties = Properties().apply {
            FileInputStream(recordFile).use { stream -> load(stream) }
        }
        val mode = runCatching {
            properties.getProperty(KEY_MODE)?.let(ConnectionBlockMode::valueOf)
        }.getOrNull() ?: return null
        return ActiveConnectionBlockRecord(
            targetHost = properties.getProperty(KEY_TARGET_HOST).orEmpty(),
            interfaceName = properties.getProperty(KEY_INTERFACE).orEmpty(),
            mode = mode,
            pid = properties.getProperty(KEY_PID)?.toLongOrNull(),
            logPath = properties.getProperty(KEY_LOG_PATH).orEmpty(),
            startedAtEpochMs = properties.getProperty(KEY_STARTED_AT)?.toLongOrNull() ?: 0L
        )
    }

    fun saveRecord(record: ActiveConnectionBlockRecord) {
        val properties = Properties().apply {
            setProperty(KEY_TARGET_HOST, record.targetHost)
            setProperty(KEY_INTERFACE, record.interfaceName)
            setProperty(KEY_MODE, record.mode.name)
            record.pid?.let { setProperty(KEY_PID, it.toString()) }
            setProperty(KEY_LOG_PATH, record.logPath)
            setProperty(KEY_STARTED_AT, record.startedAtEpochMs.toString())
        }
        FileOutputStream(recordFile).use { stream ->
            properties.store(stream, "FSploit connection block")
        }
    }

    fun clear() {
        recordFile.delete()
    }

    companion object {
        private const val RECORD_FILE_NAME = "active_block.properties"
        private const val KEY_TARGET_HOST = "target_host"
        private const val KEY_INTERFACE = "interface"
        private const val KEY_MODE = "mode"
        private const val KEY_PID = "pid"
        private const val KEY_LOG_PATH = "log_path"
        private const val KEY_STARTED_AT = "started_at"
    }
}
