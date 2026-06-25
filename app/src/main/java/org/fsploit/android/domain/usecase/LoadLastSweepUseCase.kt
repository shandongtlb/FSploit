package org.fsploit.android.domain.usecase

import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.HostScanResult

/** Restores the persisted last host sweep: the scanned-host count and the discovered targets. */
class LoadLastSweepUseCase(
    private val preferencesRepository: AppPreferencesRepository
) {
    operator fun invoke(): Pair<Int, List<HostScanResult>> {
        return preferencesRepository.getLastSweepScannedHosts() to
            preferencesRepository.getLastSweepResults()
    }
}
