package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfActionResult
import org.fsploit.android.domain.model.MsfRpcConfig

class StartMsfHandlerUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(
        config: MsfRpcConfig,
        payload: String,
        lhost: String,
        lport: String
    ): MsfActionResult = repository.startHandler(config, payload, lhost, lport)
}
