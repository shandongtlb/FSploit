package org.fsploit.android.domain.usecase

import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.ShellCommandResult

class RunShellCommandUseCase(
    private val shellRepository: ShellRepository
) {
    suspend operator fun invoke(
        command: String,
        asRoot: Boolean,
        timeoutMs: Long
    ): ShellCommandResult {
        return shellRepository.execute(command, asRoot, timeoutMs)
    }
}
