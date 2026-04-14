package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MsfRpcConfig

class SaveMsfRpcConfigUseCase(
    private val repository: AppPreferencesRepository
) {
    operator fun invoke(config: MsfRpcConfig) {
        repository.setMsfRpcConfig(config)
    }
}
