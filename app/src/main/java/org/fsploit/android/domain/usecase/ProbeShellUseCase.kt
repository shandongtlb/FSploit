package org.fsploit.android.domain.usecase

import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.ShellStatus

class ProbeShellUseCase(
    private val shellRepository: ShellRepository
) {
    operator fun invoke(): ShellStatus = shellRepository.probe()
}
