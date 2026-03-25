package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository

class GetPreferredInterfaceUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(): String = preferencesRepository.getPreferredInterfaceName()
}
