package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MitmToolchainConfig

class LoadMitmToolchainConfigUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(): MitmToolchainConfig {
        return preferencesRepository.getMitmToolchainConfig()
    }
}
