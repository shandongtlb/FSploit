package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository

class SavePreferredInterfaceUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(interfaceName: String) {
        preferencesRepository.setPreferredInterfaceName(interfaceName)
    }
}
