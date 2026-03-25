package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.ShellStatus

class LoadMitmReadinessUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(shellStatus: ShellStatus): MitmReadiness {
        return mitmRepository.loadReadiness(shellStatus)
    }
}
