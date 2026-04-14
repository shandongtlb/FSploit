package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfRpcConfig
import org.fsploit.android.domain.model.MsfRpcOverview

class LoadMsfOverviewUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(config: MsfRpcConfig): MsfRpcOverview = repository.loadOverview(config)
}
