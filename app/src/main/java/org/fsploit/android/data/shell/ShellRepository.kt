package org.fsploit.android.data.shell

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.ShellStatus
import java.util.concurrent.TimeUnit

class ShellRepository(
    private val resourceProvider: ResourceProvider
) {
    fun probe(): ShellStatus {
        val shellOk = runCommand("sh", "-c", "echo shell").contains("shell")
        val suPath = runCommand("sh", "-c", "command -v su")
        val suAvailable = suPath.isNotBlank()
        val rootCheck = if (suAvailable) runCommand("su", "-c", "id") else ""
        val rootGranted = rootCheck.contains("uid=0")

        val summary = when {
            !shellOk -> resourceProvider.getString(R.string.shell_standard_unavailable)
            rootGranted -> resourceProvider.getString(R.string.shell_root_available)
            suAvailable -> resourceProvider.getString(R.string.shell_su_present)
            else -> resourceProvider.getString(R.string.shell_no_root_tooling)
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
