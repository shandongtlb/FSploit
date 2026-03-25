package org.fsploit.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.data.network.NetworkInterfaceRepository
import org.fsploit.android.databinding.ActivityMainBinding
import org.fsploit.android.domain.model.InterfaceCategory
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    private val viewModel: HomeViewModel by viewModels {
        object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                val repository = NetworkInterfaceRepository(applicationContext)
                val useCase = LoadNetworkOverviewUseCase(repository)
                return HomeViewModel(useCase) as T
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
        binding.refreshButton.setOnClickListener {
            refresh()
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
        binding.permissionSummaryValue.text = state.permissionSummary
        binding.activeTransportValue.text = state.activeTransportLabel
        binding.statusMessage.text = state.statusMessage
        binding.requestPermissionsButton.isEnabled = !hasAllRequiredPermissions()
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
                    InterfaceCategory.WIFI -> "Wi-Fi"
                    InterfaceCategory.ETHERNET -> "Ethernet"
                    InterfaceCategory.USB -> "USB"
                    InterfaceCategory.OTHER -> "Other"
                }
                "$label: ${info.name}\n${info.addresses.joinToString()}"
            }
        }
    }

    private fun refresh() {
        viewModel.refresh(
            permissionSummary = buildPermissionSummary(),
            permissionsGranted = hasAllRequiredPermissions()
        )
    }

    private fun buildPermissionSummary(): String {
        val missing = missingPermissions()
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
}
