package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MitmToolchainConfig

class SaveMitmToolchainConfigUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(config: MitmToolchainConfig) {
        preferencesRepository.setMitmToolchainConfig(config)
    }
}
