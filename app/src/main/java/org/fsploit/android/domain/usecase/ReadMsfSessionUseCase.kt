package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfConsoleResult
import org.fsploit.android.domain.model.MsfRpcConfig

class ReadMsfSessionUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(
        config: MsfRpcConfig,
        sessionId: String,
        sessionType: String
    ): MsfConsoleResult = repository.readSession(config, sessionId, sessionType)
}
