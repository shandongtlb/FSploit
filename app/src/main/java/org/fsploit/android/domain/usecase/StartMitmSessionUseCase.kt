package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.domain.model.MitmActionResult
import org.fsploit.android.domain.model.MitmLaunchRequest

class StartMitmSessionUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(request: MitmLaunchRequest): MitmActionResult {
        return mitmRepository.startSession(request)
    }
}
