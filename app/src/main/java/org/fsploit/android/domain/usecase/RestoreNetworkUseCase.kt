package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.domain.model.MitmActionResult

/**
 * Stops every active MITM artifact (session + standalone connection block) and restores the
 * network from the stored records. Backs the foreground-service "stop all / restore network"
 * action.
 */
class RestoreNetworkUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(): MitmActionResult {
        return mitmRepository.stopAll()
    }
}
