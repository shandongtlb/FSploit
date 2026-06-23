package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfActionResult
import org.fsploit.android.domain.model.MsfRpcConfig

class WriteMsfSessionUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(
        config: MsfRpcConfig,
        sessionId: String,
        sessionType: String,
        data: String
    ): MsfActionResult = repository.writeSession(config, sessionId, sessionType, data)
}
