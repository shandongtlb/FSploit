package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.domain.model.MitmActionResult

class StopMitmSessionUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(): MitmActionResult {
        return mitmRepository.stopSession()
    }
}
