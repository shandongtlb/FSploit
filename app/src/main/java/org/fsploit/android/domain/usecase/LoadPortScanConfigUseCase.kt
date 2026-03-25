package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.PortScanConfig

class LoadPortScanConfigUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(): PortScanConfig {
        return preferencesRepository.getPortScanConfig()
    }
}
