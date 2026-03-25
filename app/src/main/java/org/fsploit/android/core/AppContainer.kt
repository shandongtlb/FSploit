package org.fsploit.android.core

import android.content.Context
import org.fsploit.android.data.mitm.BettercapPackageManager
import org.fsploit.android.data.mitm.ExternalToolMitmBackend
import org.fsploit.android.data.mitm.MitmRepository
import org.fsploit.android.data.network.HostSweepRepository
import org.fsploit.android.data.network.NetworkInterfaceRepository
import org.fsploit.android.data.network.PortScanRepository
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.usecase.BlockHostUseCase
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadMitmReadinessUseCase
import org.fsploit.android.domain.usecase.LoadMitmSessionUseCase
import org.fsploit.android.domain.usecase.LoadMitmToolchainConfigUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.SavePortScanConfigUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.SaveMitmToolchainConfigUseCase
import org.fsploit.android.domain.usecase.StartMitmSessionUseCase
import org.fsploit.android.domain.usecase.StopMitmSessionUseCase
import org.fsploit.android.domain.usecase.UnblockHostUseCase

class AppContainer(
    context: Context
) {
    val resourceProvider = AndroidResourceProvider(context)
    private val preferencesRepository = AppPreferencesRepository(context)
    val bettercapPackageManager = BettercapPackageManager(context, preferencesRepository)
    private val networkRepository = NetworkInterfaceRepository(context, resourceProvider)
    private val shellRepository = ShellRepository(resourceProvider)
    private val mitmBackend = ExternalToolMitmBackend(
        context = context,
        resourceProvider = resourceProvider,
        shellRepository = shellRepository,
        preferencesRepository = preferencesRepository
    )
    private val mitmRepository = MitmRepository(resourceProvider, shellRepository, mitmBackend)
    private val hostSweepRepository = HostSweepRepository(networkRepository, resourceProvider)
    private val portScanRepository = PortScanRepository(resourceProvider)

    val homeViewModelFactory = FSploitViewModelFactory(
        resourceProvider = resourceProvider,
        loadNetworkOverview = LoadNetworkOverviewUseCase(networkRepository),
        getPreferredInterface = GetPreferredInterfaceUseCase(preferencesRepository),
        savePreferredInterface = SavePreferredInterfaceUseCase(preferencesRepository),
        loadPortScanConfig = LoadPortScanConfigUseCase(preferencesRepository),
        savePortScanConfig = SavePortScanConfigUseCase(preferencesRepository),
        probeShell = ProbeShellUseCase(shellRepository),
        loadMitmReadiness = LoadMitmReadinessUseCase(mitmRepository),
        loadMitmSession = LoadMitmSessionUseCase(mitmRepository),
        loadMitmToolchainConfig = LoadMitmToolchainConfigUseCase(preferencesRepository),
        runHostSweep = RunHostSweepUseCase(hostSweepRepository),
        runPortScan = RunPortScanUseCase(portScanRepository),
        runShellCommand = RunShellCommandUseCase(shellRepository),
        blockHost = BlockHostUseCase(mitmRepository),
        unblockHost = UnblockHostUseCase(mitmRepository),
        saveMitmToolchainConfig = SaveMitmToolchainConfigUseCase(preferencesRepository),
        startMitmSession = StartMitmSessionUseCase(mitmRepository),
        stopMitmSession = StopMitmSessionUseCase(mitmRepository)
    )
}
