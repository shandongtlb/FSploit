package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfConsoleResult
import org.fsploit.android.domain.model.MsfRpcConfig

/**
 * Runs a curated auxiliary scanner module against [rhosts] in the shared msgrpc instance and returns
 * the captured console output. The heavy lifting stays in MSF; the app is just the convenient trigger.
 */
class RunMsfScanUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(config: MsfRpcConfig, modulePath: String, rhosts: String): MsfConsoleResult =
        repository.runScan(config, modulePath, rhosts)
}
