package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MsfRpcConfig

class LoadMsfRpcConfigUseCase(
    private val repository: AppPreferencesRepository
) {
    operator fun invoke(): MsfRpcConfig = repository.getMsfRpcConfig()
}
