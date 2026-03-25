package org.fsploit.android.domain.usecase

import org.fsploit.android.data.network.NetworkInterfaceRepository
import org.fsploit.android.domain.model.NetworkOverview

class LoadNetworkOverviewUseCase(
    private val repository: NetworkInterfaceRepository
) {
    operator fun invoke(): NetworkOverview = repository.loadOverview()
}
