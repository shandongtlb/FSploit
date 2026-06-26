package org.fsploit.android.domain.usecase

import org.fsploit.android.data.mitm.MitmRepository

/**
 * Returns the currently blocked host (reconciled against live process / iptables state), or an
 * empty string when nothing is blocked. Lets the UI rebuild connection-block state after a restart.
 */
class LoadActiveBlockUseCase(
    private val mitmRepository: MitmRepository
) {
    operator fun invoke(): String = mitmRepository.loadActiveBlock()
}
