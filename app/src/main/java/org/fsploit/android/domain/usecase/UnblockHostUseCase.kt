package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.domain.model.ConnectionBlockResult

class UnblockHostUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(hostAddress: String): ConnectionBlockResult {
        return mitmRepository.unblockHost(hostAddress)
    }
}
