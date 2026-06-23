package org.fsploit.android.core

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.fsploit.android.domain.usecase.BlockHostUseCase
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadMitmReadinessUseCase
import org.fsploit.android.domain.usecase.LoadMitmSessionUseCase
import org.fsploit.android.domain.usecase.LoadMitmToolchainConfigUseCase
import org.fsploit.android.domain.usecase.LoadMsfOverviewUseCase
import org.fsploit.android.domain.usecase.LoadMsfRpcConfigUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SaveMitmToolchainConfigUseCase
import org.fsploit.android.domain.usecase.SaveMsfRpcConfigUseCase
import org.fsploit.android.domain.usecase.SavePortScanConfigUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.StartMitmSessionUseCase
import org.fsploit.android.domain.usecase.StopMitmSessionUseCase
import org.fsploit.android.domain.usecase.UnblockHostUseCase
import org.fsploit.android.feature.mitm.MitmViewModel
import org.fsploit.android.feature.msf.MsfViewModel
import org.fsploit.android.feature.session.SessionStateHolder
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.feature.settings.SettingsViewModel
import org.fsploit.android.feature.target.TargetDetailViewModel
import org.fsploit.android.feature.tools.ToolsViewModel

/**
 * Single factory for every activity-scoped ViewModel. The shared cross-screen state lives in
 * [sessionStateHolder]; [SessionViewModel] orchestrates it and each per-feature ViewModel reads it.
 */
class FSploitViewModelFactory(
    private val resourceProvider: ResourceProvider,
    private val sessionStateHolder: SessionStateHolder,
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterface: SavePreferredInterfaceUseCase,
    private val loadPortScanConfig: LoadPortScanConfigUseCase,
    private val savePortScanConfig: SavePortScanConfigUseCase,
    private val probeShell: ProbeShellUseCase,
    private val loadMitmReadiness: LoadMitmReadinessUseCase,
    private val loadMitmSession: LoadMitmSessionUseCase,
    private val loadMitmToolchainConfig: LoadMitmToolchainConfigUseCase,
    private val loadMsfOverview: LoadMsfOverviewUseCase,
    private val loadMsfRpcConfig: LoadMsfRpcConfigUseCase,
    private val runHostSweep: RunHostSweepUseCase,
    private val runPortScan: RunPortScanUseCase,
    private val runShellCommand: RunShellCommandUseCase,
    private val blockHost: BlockHostUseCase,
    private val unblockHost: UnblockHostUseCase,
    private val saveMitmToolchainConfig: SaveMitmToolchainConfigUseCase,
    private val saveMsfRpcConfig: SaveMsfRpcConfigUseCase,
    private val startMitmSession: StartMitmSessionUseCase,
    private val stopMitmSession: StopMitmSessionUseCase
) : ViewModelProvider.Factory {

    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return when {
            modelClass.isAssignableFrom(SessionViewModel::class.java) -> SessionViewModel(
                resourceProvider = resourceProvider,
                holder = sessionStateHolder,
                loadNetworkOverview = loadNetworkOverview,
                getPreferredInterface = getPreferredInterface,
                savePreferredInterfaceUseCase = savePreferredInterface,
                probeShell = probeShell,
                runHostSweep = runHostSweep
            ) as T

            modelClass.isAssignableFrom(MitmViewModel::class.java) -> MitmViewModel(
                resourceProvider = resourceProvider,
                session = sessionStateHolder,
                loadMitmReadinessUseCase = loadMitmReadiness,
                loadMitmSessionUseCase = loadMitmSession,
                blockHostUseCase = blockHost,
                unblockHostUseCase = unblockHost,
                startMitmSessionUseCase = startMitmSession,
                stopMitmSessionUseCase = stopMitmSession,
                runShellCommandUseCase = runShellCommand
            ) as T

            modelClass.isAssignableFrom(MsfViewModel::class.java) -> MsfViewModel(
                resourceProvider = resourceProvider,
                session = sessionStateHolder,
                loadMsfRpcConfigUseCase = loadMsfRpcConfig,
                loadMsfOverviewUseCase = loadMsfOverview,
                saveMsfRpcConfigUseCase = saveMsfRpcConfig,
                runShellCommandUseCase = runShellCommand
            ) as T

            modelClass.isAssignableFrom(ToolsViewModel::class.java) -> ToolsViewModel(
                resourceProvider = resourceProvider,
                session = sessionStateHolder,
                runShellCommandUseCase = runShellCommand
            ) as T

            modelClass.isAssignableFrom(TargetDetailViewModel::class.java) -> TargetDetailViewModel(
                resourceProvider = resourceProvider,
                session = sessionStateHolder,
                loadPortScanConfig = loadPortScanConfig,
                savePortScanConfig = savePortScanConfig,
                runPortScanUseCase = runPortScan
            ) as T

            modelClass.isAssignableFrom(SettingsViewModel::class.java) -> SettingsViewModel(
                resourceProvider = resourceProvider,
                loadMitmToolchainConfig = loadMitmToolchainConfig,
                saveMitmToolchainConfigUseCase = saveMitmToolchainConfig,
                loadPortScanConfig = loadPortScanConfig
            ) as T

            else -> throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
        }
    }
}
