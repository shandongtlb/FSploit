package org.fsploit.android.feature.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.MitmToolchainConfig
import org.fsploit.android.domain.model.PortScanConfig
import org.fsploit.android.domain.usecase.LoadMitmToolchainConfigUseCase
import org.fsploit.android.domain.usecase.LoadPortScanConfigUseCase
import org.fsploit.android.domain.usecase.SaveMitmToolchainConfigUseCase

data class SettingsUiState(
    val mitmToolchainConfig: MitmToolchainConfig = MitmToolchainConfig(),
    val portScanConfig: PortScanConfig = PortScanConfig(portSpec = "", connectTimeoutMs = 0, parallelism = 0),
    val mitmSettingsSummary: String = "",
    val isSavingMitmToolchainConfig: Boolean = false
)

class SettingsViewModel(
    private val resourceProvider: ResourceProvider,
    private val loadMitmToolchainConfig: LoadMitmToolchainConfigUseCase,
    private val saveMitmToolchainConfigUseCase: SaveMitmToolchainConfigUseCase,
    private val loadPortScanConfig: LoadPortScanConfigUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        SettingsUiState(
            mitmSettingsSummary = resourceProvider.getString(R.string.mitm_settings_idle)
        )
    )
    val uiState: StateFlow<SettingsUiState> = _uiState.asStateFlow()

    fun refresh() {
        _uiState.value = _uiState.value.copy(
            mitmToolchainConfig = loadMitmToolchainConfig(),
            portScanConfig = loadPortScanConfig()
        )
    }

    fun updateMitmBettercapPath(value: String) {
        _uiState.value = _uiState.value.copy(
            mitmToolchainConfig = _uiState.value.mitmToolchainConfig.copy(bettercapPath = value)
        )
    }

    fun updateMitmTcpdumpPath(value: String) {
        _uiState.value = _uiState.value.copy(
            mitmToolchainConfig = _uiState.value.mitmToolchainConfig.copy(tcpdumpPath = value)
        )
    }

    fun updateMitmMitmdumpPath(value: String) {
        _uiState.value = _uiState.value.copy(
            mitmToolchainConfig = _uiState.value.mitmToolchainConfig.copy(mitmdumpPath = value)
        )
    }

    fun updateMitmHttpRedirectPort(value: String) {
        val parsed = value.trim().toIntOrNull() ?: 0
        _uiState.value = _uiState.value.copy(
            mitmToolchainConfig = _uiState.value.mitmToolchainConfig.copy(httpRedirectPort = parsed)
        )
    }

    fun saveMitmToolchainConfig() {
        val config = _uiState.value.mitmToolchainConfig
        val port = config.httpRedirectPort
        if (port !in 1..65535) {
            _uiState.value = _uiState.value.copy(
                mitmSettingsSummary = resourceProvider.getString(R.string.mitm_redirect_port_invalid)
            )
            return
        }
        if (
            config.bettercapPath.trim().isEmpty() ||
            config.tcpdumpPath.trim().isEmpty() ||
            config.mitmdumpPath.trim().isEmpty()
        ) {
            _uiState.value = _uiState.value.copy(
                mitmSettingsSummary = resourceProvider.getString(R.string.mitm_settings_paths_required)
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isSavingMitmToolchainConfig = true,
                mitmSettingsSummary = resourceProvider.getString(R.string.mitm_settings_saving)
            )

            withContext(Dispatchers.IO) {
                saveMitmToolchainConfigUseCase(
                    config.copy(
                        bettercapPath = config.bettercapPath.trim(),
                        tcpdumpPath = config.tcpdumpPath.trim(),
                        mitmdumpPath = config.mitmdumpPath.trim()
                    )
                )
            }

            _uiState.value = _uiState.value.copy(
                isSavingMitmToolchainConfig = false,
                mitmSettingsSummary = resourceProvider.getString(R.string.mitm_settings_saved)
            )
        }
    }
}
