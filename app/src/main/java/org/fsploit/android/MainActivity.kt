package org.fsploit.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.activity.OnBackPressedCallback
import androidx.appcompat.app.ActionBarDrawerToggle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.GravityCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.ViewModelProvider
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import kotlinx.coroutines.launch
import org.fsploit.android.data.mitm.BettercapPackageManager
import org.fsploit.android.databinding.ActivityMainBinding
import org.fsploit.android.feature.discovery.DiscoveryFragment
import org.fsploit.android.feature.home.HomeViewModel
import org.fsploit.android.feature.mitm.MitmFragment
import org.fsploit.android.feature.overview.OverviewFragment
import org.fsploit.android.feature.settings.SettingsFragment
import org.fsploit.android.feature.target.TargetDetailFragment
import org.fsploit.android.feature.tools.ToolsFragment

class MainActivity : AppCompatActivity() {

    lateinit var viewModelFactory: ViewModelProvider.Factory
        private set

    private lateinit var bettercapPackageManager: BettercapPackageManager
    private lateinit var binding: ActivityMainBinding
    private lateinit var drawerToggle: ActionBarDrawerToggle
    private var currentScreen: MainScreen = MainScreen.OVERVIEW
    private var bettercapPromptHandled = false

    private val viewModel: HomeViewModel by viewModels { viewModelFactory }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) {
        refreshFromUi()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        val appContainer = (application as FSploitApp).appContainer
        viewModelFactory = appContainer.homeViewModelFactory
        bettercapPackageManager = appContainer.bettercapPackageManager
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)

        drawerToggle = ActionBarDrawerToggle(
            this,
            binding.drawerLayout,
            binding.toolbar,
            R.string.drawer_open,
            R.string.drawer_close
        )
        binding.drawerLayout.addDrawerListener(drawerToggle)
        drawerToggle.syncState()

        ViewCompat.setOnApplyWindowInsetsListener(binding.drawerLayout) { _, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            binding.contentContainer.setPadding(0, bars.top, 0, bars.bottom)
            binding.navigationView.setPadding(0, bars.top, 0, bars.bottom)
            insets
        }

        binding.navigationView.setNavigationItemSelectedListener { item ->
            MainScreen.fromMenuItemId(item.itemId)?.let { openScreen(it) }
            binding.drawerLayout.closeDrawer(GravityCompat.START)
            true
        }
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (binding.drawerLayout.isDrawerOpen(GravityCompat.START)) {
                    binding.drawerLayout.closeDrawer(GravityCompat.START)
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                    isEnabled = true
                }
            }
        })

        currentScreen = savedInstanceState?.getString(KEY_SCREEN)
            ?.let(MainScreen::valueOf)
            ?: MainScreen.OVERVIEW

        if (savedInstanceState == null) {
            openScreen(currentScreen, commitNow = true)
        } else {
            updateScreenUi(currentScreen)
        }

        if (!hasAllRequiredPermissionsForUi()) {
            requestPermissionsFromUi()
        } else {
            refreshFromUi()
        }
        if (bettercapPackageManager.syncInstalledBinaryPath()) {
            refreshFromUi()
        }
        maybePromptBettercapDownload()
    }

    override fun onResume() {
        super.onResume()
        refreshFromUi()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_SCREEN, currentScreen.name)
    }

    fun openScreen(screen: MainScreen, commitNow: Boolean = false) {
        currentScreen = screen
        updateScreenUi(screen)
        val fragment = when (screen) {
            MainScreen.OVERVIEW -> OverviewFragment()
            MainScreen.MITM -> MitmFragment()
            MainScreen.DISCOVERY -> DiscoveryFragment()
            MainScreen.TARGET_DETAIL -> TargetDetailFragment()
            MainScreen.TOOLS -> ToolsFragment()
            MainScreen.SETTINGS -> SettingsFragment()
        }

        supportFragmentManager.beginTransaction()
            .replace(R.id.contentFrame, fragment, screen.name)
            .run {
                if (commitNow) commitNow() else commit()
            }
    }

    fun requestPermissionsFromUi() {
        val missing = missingPermissions()
        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing.toTypedArray())
        }
    }

    fun refreshFromUi() {
        viewModel.refresh(
            permissionSummary = buildPermissionSummary(),
            permissionsGranted = hasAllRequiredPermissionsForUi()
        )
    }

    fun hasAllRequiredPermissionsForUi(): Boolean = missingPermissions().isEmpty()

    private fun updateScreenUi(screen: MainScreen) {
        binding.navigationView.setCheckedItem(screen.menuItemId)
        supportActionBar?.title = getString(screen.titleRes)
        supportActionBar?.subtitle = getString(R.string.app_subtitle)
    }

    private fun buildPermissionSummary(): String {
        val missing = missingPermissions().map(::permissionDisplayName)
        return if (missing.isEmpty()) {
            getString(R.string.permissions_granted)
        } else {
            getString(R.string.permissions_missing, missing.joinToString())
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

    private fun maybePromptBettercapDownload() {
        if (bettercapPromptHandled || !bettercapPackageManager.shouldOfferManagedDownload()) {
            return
        }
        bettercapPromptHandled = true
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.bettercap_download_title)
            .setMessage(R.string.bettercap_download_message)
            .setPositiveButton(R.string.bettercap_download_action) { _, _ ->
                downloadManagedBettercap()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun downloadManagedBettercap() {
        val progressDialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.bettercap_download_progress_title)
            .setMessage(R.string.bettercap_download_progress_message)
            .setCancelable(false)
            .create()
        progressDialog.show()

        lifecycleScope.launch {
            val result = bettercapPackageManager.downloadManagedPackage()
            progressDialog.dismiss()
            result.onSuccess {
                refreshFromUi()
                Toast.makeText(
                    this@MainActivity,
                    getString(R.string.bettercap_download_success),
                    Toast.LENGTH_LONG
                ).show()
            }.onFailure { exception ->
                bettercapPromptHandled = false
                MaterialAlertDialogBuilder(this@MainActivity)
                    .setTitle(R.string.bettercap_download_failed_title)
                    .setMessage(
                        getString(
                            R.string.bettercap_download_failed_message,
                            exception.message ?: exception.javaClass.simpleName
                        )
                    )
                    .setPositiveButton(R.string.bettercap_download_retry) { _, _ ->
                        bettercapPromptHandled = true
                        downloadManagedBettercap()
                    }
                    .setNegativeButton(android.R.string.cancel, null)
                    .show()
            }
        }
    }

    companion object {
        private const val KEY_SCREEN = "screen"
    }
}
