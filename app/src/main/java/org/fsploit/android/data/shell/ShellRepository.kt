package org.fsploit.android.data.shell

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.ShellCommandResult
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

    fun execute(
        command: String,
        asRoot: Boolean,
        timeoutMs: Long
    ): ShellCommandResult {
        val sanitizedCommand = command.trim()
        if (sanitizedCommand.isEmpty()) {
            return ShellCommandResult(
                command = "",
                output = "",
                exitCode = null,
                timedOut = false,
                executedAsRoot = asRoot,
                summary = resourceProvider.getString(R.string.shell_command_empty)
            )
        }

        return try {
            val shellBinary = if (asRoot) "su" else "sh"
            val process = ProcessBuilder(shellBinary, "-c", sanitizedCommand)
                .redirectErrorStream(true)
                .start()

            val completed = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
            if (!completed) {
                process.destroyForcibly()
                ShellCommandResult(
                    command = sanitizedCommand,
                    output = "",
                    exitCode = null,
                    timedOut = true,
                    executedAsRoot = asRoot,
                    summary = resourceProvider.getString(
                        R.string.shell_command_timed_out,
                        timeoutMs
                    )
                )
            } else {
                val output = process.inputStream.bufferedReader().use { it.readText().trim() }
                val exitCode = process.exitValue()
                ShellCommandResult(
                    command = sanitizedCommand,
                    output = output,
                    exitCode = exitCode,
                    timedOut = false,
                    executedAsRoot = asRoot,
                    summary = if (exitCode == 0) {
                        resourceProvider.getString(
                            R.string.shell_command_success,
                            if (asRoot) {
                                resourceProvider.getString(R.string.shell_mode_root)
                            } else {
                                resourceProvider.getString(R.string.shell_mode_standard)
                            }
                        )
                    } else {
                        resourceProvider.getString(
                            R.string.shell_command_exit_code,
                            exitCode
                        )
                    }
                )
            }
        } catch (exception: Exception) {
            ShellCommandResult(
                command = sanitizedCommand,
                output = exception.stackTraceToString(),
                exitCode = null,
                timedOut = false,
                executedAsRoot = asRoot,
                summary = resourceProvider.getString(
                    R.string.shell_command_failed,
                    exception.javaClass.simpleName
                )
            )
        }
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
