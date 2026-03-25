package org.fsploit.android.data.shell

import org.fsploit.android.domain.model.ShellStatus
import java.util.concurrent.TimeUnit

class ShellRepository {
    fun probe(): ShellStatus {
        val shellOk = runCommand("sh", "-c", "echo shell").contains("shell")
        val suPath = runCommand("sh", "-c", "command -v su")
        val suAvailable = suPath.isNotBlank()
        val rootCheck = if (suAvailable) runCommand("su", "-c", "id") else ""
        val rootGranted = rootCheck.contains("uid=0")

        val summary = when {
            !shellOk -> "The standard shell is unavailable."
            rootGranted -> "Root shell is available."
            suAvailable -> "su is present, but root was not granted."
            else -> "Root tooling is not available on this device."
        }

        return ShellStatus(
            shellAvailable = shellOk,
            suAvailable = suAvailable,
            rootGranted = rootGranted,
            summary = summary
        )
    }

    private fun runCommand(vararg command: String): String {
        return try {
            val process = ProcessBuilder(*command)
                .redirectErrorStream(true)
                .start()

            if (!process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly()
                return ""
            }

            process.inputStream.bufferedReader().use { it.readText().trim() }
        } catch (_: Exception) {
            ""
        }
    }
}
