package org.fsploit.android.data.shell

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.ShellCommandResult
import org.fsploit.android.domain.model.ShellStatus
import kotlin.concurrent.thread
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
            val result = runProcess(timeoutMs, if (asRoot) "su" else "sh", "-c", sanitizedCommand)
            if (result.timedOut) {
                ShellCommandResult(
                    command = sanitizedCommand,
                    output = result.output,
                    exitCode = null,
                    timedOut = true,
                    executedAsRoot = asRoot,
                    summary = resourceProvider.getString(
                        R.string.shell_command_timed_out,
                        timeoutMs
                    )
                )
            } else {
                val exitCode = result.exitCode ?: -1
                ShellCommandResult(
                    command = sanitizedCommand,
                    output = result.output,
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
            val result = runProcess(2_000L, *command)
            if (result.timedOut) "" else result.output
        } catch (_: Exception) {
            ""
        }
    }

    private fun runProcess(timeoutMs: Long, vararg command: String): ProcessResult {
        val process = ProcessBuilder(*command)
            .redirectErrorStream(true)
            .start()

        val outputBuffer = StringBuilder()
        val readerThread = thread(start = true, isDaemon = true) {
            process.inputStream.bufferedReader().use { reader ->
                val buffer = CharArray(DEFAULT_BUFFER_SIZE)
                while (true) {
                    val read = reader.read(buffer)
                    if (read < 0) {
                        break
                    }
                    if (read > 0) {
                        synchronized(outputBuffer) {
                            outputBuffer.append(buffer, 0, read)
                        }
                    }
                }
            }
        }

        val completed = process.waitFor(timeoutMs, TimeUnit.MILLISECONDS)
        if (!completed) {
            process.destroyForcibly()
        }
        process.waitFor(PROCESS_EXIT_GRACE_MS, TimeUnit.MILLISECONDS)
        readerThread.join(OUTPUT_JOIN_TIMEOUT_MS)

        val output = synchronized(outputBuffer) { outputBuffer.toString().trim() }
        val exitCode = if (process.isAlive) {
            null
        } else {
            runCatching { process.exitValue() }.getOrNull()
        }
        return ProcessResult(
            output = output,
            exitCode = exitCode,
            timedOut = !completed
        )
    }

    private data class ProcessResult(
        val output: String,
        val exitCode: Int?,
        val timedOut: Boolean
    )

    companion object {
        private const val PROCESS_EXIT_GRACE_MS = 500L
        private const val OUTPUT_JOIN_TIMEOUT_MS = 500L
    }
}
