package org.fsploit.android.domain.usecase

import org.fsploit.android.data.network.HostSweepRepository
import org.fsploit.android.domain.model.HostSweepReport

class RunHostSweepUseCase(
    private val hostSweepRepository: HostSweepRepository
) {
    suspend operator fun invoke(
        preferredInterfaceName: String,
        onProgress: (scanned: Int, total: Int) -> Unit = { _, _ -> }
    ): HostSweepReport {
        return hostSweepRepository.runSweep(preferredInterfaceName, onProgress)
    }
}
