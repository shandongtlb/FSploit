package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfRpcConfig

class ProbeMsfConnectionUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(config: MsfRpcConfig): Boolean = repository.isReachable(config)
}
