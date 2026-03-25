package org.fsploit.android.core

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SavePortScanConfigUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase
import org.fsploit.android.feature.home.HomeViewModel

class FSploitViewModelFactory(
    private val resourceProvider: ResourceProvider,
    private val loadNetworkOverview: LoadNetworkOverviewUseCase,
    private val getPreferredInterface: GetPreferredInterfaceUseCase,
    private val savePreferredInterface: SavePreferredInterfaceUseCase,
    private val loadPortScanConfig: LoadPortScanConfigUseCase,
    private val savePortScanConfig: SavePortScanConfigUseCase,
    private val probeShell: ProbeShellUseCase,
    private val runHostSweep: RunHostSweepUseCase,
    private val runPortScan: RunPortScanUseCase,
    private val runShellCommand: RunShellCommandUseCase
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
                    runHostSweep = runHostSweep,
                    runPortScanUseCase = runPortScan,
                    runShellCommandUseCase = runShellCommand
                ) as T
            }

            else -> throw IllegalArgumentException("Unknown ViewModel class: ${modelClass.name}")
        }
    }
}
