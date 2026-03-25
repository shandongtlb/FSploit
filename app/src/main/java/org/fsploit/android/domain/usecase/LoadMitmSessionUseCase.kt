package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.domain.model.MitmSession

class LoadMitmSessionUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(): MitmSession {
        return mitmRepository.loadSession()
    }
}
