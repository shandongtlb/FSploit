package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.HostScanResult

/** Persists the latest host sweep so the discovered-target list survives process death. */
class SaveLastSweepUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(scannedHosts: Int, hosts: List<HostScanResult>) {
        preferencesRepository.setLastSweep(scannedHosts, hosts)
    }
}
