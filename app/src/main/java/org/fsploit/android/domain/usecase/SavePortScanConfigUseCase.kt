package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.PortScanConfig

class SavePortScanConfigUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(config: PortScanConfig) {
        preferencesRepository.setPortScanConfig(config)
    }
}
