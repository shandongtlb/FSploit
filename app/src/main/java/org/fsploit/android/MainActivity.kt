package org.fsploit.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.ArrayAdapter
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.core.AndroidResourceProvider
import org.fsploit.android.data.network.HostSweepRepository
import org.fsploit.android.data.network.NetworkInterfaceRepository
import org.fsploit.android.data.network.PortScanRepository
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.databinding.ActivityMainBinding
import org.fsploit.android.domain.model.InterfaceCategory
import org.fsploit.android.domain.usecase.GetPreferredInterfaceUseCase
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.domain.usecase.ProbeShellUseCase
import org.fsploit.android.domain.usecase.RunHostSweepUseCase
import org.fsploit.android.domain.usecase.RunPortScanUseCase
import org.fsploit.android.domain.usecase.SavePreferredInterfaceUseCase
import org.fsploit.android.feature.home.HomeSection
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val viewModel: HomeViewModel by viewModels {
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                val resourceProvider = AndroidResourceProvider(applicationContext)
                val networkRepository = NetworkInterfaceRepository(applicationContext, resourceProvider)
                val shellRepository = ShellRepository(resourceProvider)
                val preferencesRepository = AppPreferencesRepository(applicationContext)

                return HomeViewModel(
                    resourceProvider = resourceProvider,
                    loadNetworkOverview = LoadNetworkOverviewUseCase(networkRepository),
                    getPreferredInterface = GetPreferredInterfaceUseCase(preferencesRepository),
                    savePreferredInterfaceUseCase = SavePreferredInterfaceUseCase(preferencesRepository),
                    probeShell = ProbeShellUseCase(shellRepository),
                    runHostSweep = RunHostSweepUseCase(
                        HostSweepRepository(networkRepository, resourceProvider)
                    ),
                    runPortScanUseCase = RunPortScanUseCase(PortScanRepository(resourceProvider))
                ) as T
            }
        }
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        refresh()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }

        binding.requestPermissionsButton.setOnClickListener {
            requestRequiredPermissions()
        }
        binding.saveInterfaceButton.setOnClickListener {
            viewModel.savePreferredInterface(binding.preferredInterfaceInput.text?.toString().orEmpty())
        }
        binding.runSweepButton.setOnClickListener {
            viewModel.savePreferredInterface(binding.preferredInterfaceInput.text?.toString().orEmpty())
            viewModel.runSweep()
        }
        binding.runPortScanButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.runPortScan()
        }
        binding.refreshButton.setOnClickListener {
            refresh()
        }
        binding.breadcrumbOverviewButton.setOnClickListener {
            viewModel.selectSection(HomeSection.OVERVIEW)
        }
        binding.breadcrumbDiscoveryButton.setOnClickListener {
            viewModel.selectSection(HomeSection.DISCOVERY)
        }
        binding.breadcrumbPortsButton.setOnClickListener {
            viewModel.selectSection(HomeSection.PORTS)
        }
        binding.targetHostInput.setOnItemClickListener { _, _, position, _ ->
            val selected = binding.targetHostInput.adapter.getItem(position)?.toString().orEmpty()
            viewModel.selectHost(selected)
        }

        lifecycleScope.launch {
            repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }

        if (!hasAllRequiredPermissions()) {
            requestRequiredPermissions()
        } else {
            refresh()
        }
    }

    private fun render(state: HomeUiState) {
        val sectionTitle = when (state.selectedSection) {
            HomeSection.OVERVIEW -> getString(R.string.section_overview_title)
            HomeSection.DISCOVERY -> getString(R.string.section_discovery_title)
            HomeSection.PORTS -> getString(R.string.section_ports_title)
        }

        binding.breadcrumbValue.text = getString(
            R.string.breadcrumb_path,
            getString(R.string.breadcrumb_root),
            sectionTitle
        )
        binding.sectionTitleValue.text = sectionTitle
        binding.overviewSection.isVisible = state.selectedSection == HomeSection.OVERVIEW
        binding.discoverySection.isVisible = state.selectedSection == HomeSection.DISCOVERY
        binding.portsSection.isVisible = state.selectedSection == HomeSection.PORTS
        binding.breadcrumbOverviewButton.isEnabled = state.selectedSection != HomeSection.OVERVIEW
        binding.breadcrumbDiscoveryButton.isEnabled = state.selectedSection != HomeSection.DISCOVERY
        binding.breadcrumbPortsButton.isEnabled = state.selectedSection != HomeSection.PORTS

        binding.permissionSummaryValue.text = state.permissionSummary
        binding.activeTransportValue.text = state.activeTransportLabel
        binding.statusMessage.text = state.statusMessage
        binding.discoveryHint.text = getString(R.string.discovery_hint)
        binding.portsHint.text = getString(R.string.ports_hint)
        binding.shellSummaryValue.text = state.shellSummary
        binding.requestPermissionsButton.isEnabled = !hasAllRequiredPermissions()
        binding.runSweepButton.isEnabled = state.canContinue && !state.isScanning
        binding.saveInterfaceButton.isEnabled = state.interfaces.isNotEmpty()
        binding.runPortScanButton.isEnabled = state.canContinue &&
            state.selectedHostAddress.isNotBlank() &&
            !state.isScanning &&
            !state.isPortScanning
        binding.continueHint.text = if (state.canContinue) {
            getString(R.string.home_ready)
        } else {
            getString(R.string.home_not_ready)
        }

        binding.interfaceListValue.text = if (state.interfaces.isEmpty()) {
            getString(R.string.no_interfaces_found)
        } else {
            state.interfaces.joinToString(separator = "\n\n") { info ->
                val label = when (info.category) {
                    InterfaceCategory.WIFI -> getString(R.string.category_wifi)
                    InterfaceCategory.ETHERNET -> getString(R.string.category_ethernet)
                    InterfaceCategory.USB -> getString(R.string.category_usb)
                    InterfaceCategory.OTHER -> getString(R.string.category_other)
                }
                "$label: ${info.name}\n${info.addresses.joinToString()}"
            }
        }

        val interfaceNames = state.interfaces.map { it.name }
        binding.preferredInterfaceInput.setAdapter(
            ArrayAdapter(
                this,
                android.R.layout.simple_dropdown_item_1line,
                interfaceNames
            )
        )
        if (binding.preferredInterfaceInput.text?.toString() != state.preferredInterfaceName) {
            binding.preferredInterfaceInput.setText(state.preferredInterfaceName, false)
        }
        binding.preferredInterfaceInput.isEnabled = state.interfaces.isNotEmpty()

        binding.scanSummaryValue.text = state.scanSummary
        binding.scanResultsValue.text = if (state.scanResults.isEmpty()) {
            getString(R.string.no_scan_results)
        } else {
            state.scanResults.joinToString(separator = "\n")
        }

        binding.targetHostInput.setAdapter(
            ArrayAdapter(
                this,
                android.R.layout.simple_dropdown_item_1line,
                state.responsiveHosts
            )
        )
        if (binding.targetHostInput.text?.toString() != state.selectedHostAddress) {
            binding.targetHostInput.setText(state.selectedHostAddress, false)
        }
        binding.targetHostInput.isEnabled = state.responsiveHosts.isNotEmpty()

        binding.portScanSummaryValue.text = state.portScanSummary
        binding.portScanResultsValue.text = if (state.portScanResults.isEmpty()) {
            if (state.responsiveHosts.isEmpty()) {
                getString(R.string.no_target_hosts)
            } else {
                getString(R.string.no_port_scan_results)
            }
        } else {
            state.portScanResults.joinToString(separator = "\n")
        }
    }

    private fun refresh() {
        viewModel.refresh(
            permissionSummary = buildPermissionSummary(),
            permissionsGranted = hasAllRequiredPermissions()
        )
    }

    private fun buildPermissionSummary(): String {
        val missing = missingPermissions().map(::permissionDisplayName)
        return if (missing.isEmpty()) {
            getString(R.string.permissions_granted)
        } else {
            getString(R.string.permissions_missing, missing.joinToString())
        }
    }

    private fun hasAllRequiredPermissions(): Boolean = missingPermissions().isEmpty()

    private fun requestRequiredPermissions() {
        val missing = missingPermissions()
        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing.toTypedArray())
        }
    }

    private fun missingPermissions(): List<String> {
        val result = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            result += Manifest.permission.ACCESS_FINE_LOCATION
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.NEARBY_WIFI_DEVICES) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            result += Manifest.permission.NEARBY_WIFI_DEVICES
        }
        return result
    }

    private fun permissionDisplayName(permission: String): String {
        return when (permission) {
            Manifest.permission.ACCESS_FINE_LOCATION ->
                getString(R.string.permission_location)
            Manifest.permission.NEARBY_WIFI_DEVICES ->
                getString(R.string.permission_nearby_wifi)
            else -> permission
        }
    }
}
