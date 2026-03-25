package org.fsploit.android.domain.usecase

import org.fsploit.android.data.network.PortScanRepository
import org.fsploit.android.domain.model.PortScanConfig
import org.fsploit.android.domain.model.PortScanReport

class RunPortScanUseCase(
    private val portScanRepository: PortScanRepository
) {
    suspend operator fun invoke(
        hostAddress: String,
        config: PortScanConfig
    ): PortScanReport {
        return portScanRepository.scan(hostAddress, config)
    }
}
