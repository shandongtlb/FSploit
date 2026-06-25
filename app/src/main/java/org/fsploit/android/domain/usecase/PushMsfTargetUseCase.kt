package org.fsploit.android.domain.usecase

import org.fsploit.android.data.msf.MsfRepository
import org.fsploit.android.domain.model.MsfActionResult
import org.fsploit.android.domain.model.MsfRpcConfig

/**
 * Hands the workbench's selected host to the shared msgrpc instance via `core.setg RHOSTS`,
 * so the operator can switch to the NetHunter terminal and `use` a module with the target
 * already populated. This is the core of the "handoff" role — the app primes context, the
 * heavy interaction stays in the terminal.
 */
class PushMsfTargetUseCase(
    private val repository: MsfRepository
) {
    operator fun invoke(config: MsfRpcConfig, host: String): MsfActionResult =
        repository.pushTarget(config, host)
}
