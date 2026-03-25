package org.fsploit.android.core

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.BlockHostUseCase
import org.fsploit.android.domain.usecase.LoadMitmReadinessUseCase
import org.fsploit.android.domain.usecase.LoadMitmSessionUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SavePortScanConfigUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.StartMitmSessionUseCase
import org.fsploit.android.domain.usecase.StopMitmSessionUseCase
import org.fsploit.android.domain.usecase.UnblockHostUseCase
import org.fsploit.android.feature.home.HomeViewModel

class FSploitViewModelFactory(
    private val resourceProvider: ResourceProvider,
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterface: SavePreferredInterfaceUseCase,
    private val loadPortScanConfig: LoadPortScanConfigUseCase,
    private val savePortScanConfig: SavePortScanConfigUseCase,
    private val probeShell: ProbeShellUseCase,
    private val loadMitmReadiness: LoadMitmReadinessUseCase,
    private val loadMitmSession: LoadMitmSessionUseCase,
    private val runHostSweep: RunHostSweepUseCase,
    private val runPortScan: RunPortScanUseCase,
    private val runShellCommand: RunShellCommandUseCase,
    private val blockHost: BlockHostUseCase,
    private val unblockHost: UnblockHostUseCase,
    private val startMitmSession: StartMitmSessionUseCase,
    private val stopMitmSession: StopMitmSessionUseCase
) : ViewModelProvider.Factory {

    @Suppress("UNCHECKED_CAST")
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return when {
            modelClass.isAssignableFrom(HomeViewModel::class.java) -> {
                HomeViewModel(
                    resourceProvider = resourceProvider,
                    loadNetworkOverview = loadNetworkOverview,
                    getPreferredInterface = getPreferredInterface,
                    savePreferredInterfaceUseCase = savePreferredInterface,
                    loadPortScanConfig = loadPortScanConfig,
                    savePortScanConfig = savePortScanConfig,
                    probeShell = probeShell,
                    loadMitmReadinessUseCase = loadMitmReadiness,
                    loadMitmSessionUseCase = loadMitmSession,
                    runHostSweep = runHostSweep,
                    runPortScanUseCase = runPortScan,
                    runShellCommandUseCase = runShellCommand,
                    blockHostUseCase = blockHost,
                    unblockHostUseCase = unblockHost,
                    startMitmSessionUseCase = startMitmSession,
                    stopMitmSessionUseCase = stopMitmSession
                ) as T
            }

            else -> throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
        }
    }
}
