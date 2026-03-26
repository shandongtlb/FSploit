package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.domain.model.ConnectionBlockResult

class BlockHostUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(hostAddress: String, interfaceName: String): ConnectionBlockResult {
        return mitmRepository.blockHost(hostAddress, interfaceName)
    }
}
