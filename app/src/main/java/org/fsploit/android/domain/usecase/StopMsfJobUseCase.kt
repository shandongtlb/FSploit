package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfActionResult
import org.fsploit.android.domain.model.MsfRpcConfig

class StopMsfJobUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(config: MsfRpcConfig, jobId: String): MsfActionResult =
        repository.stopJob(config, jobId)
}
