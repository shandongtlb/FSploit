package org.fsploit.android.feature.home

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.fsploit.android.domain.usecase.LoadNetworkOverviewUseCase

class HomeViewModel(
    private val loadNetworkOverview: LoadNetworkOverviewUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(HomeUiState())
    val uiState: StateFlow<HomeUiState> = _uiState.asStateFlow()

    fun refresh(permissionSummary: String, permissionsGranted: Boolean) {
        viewModelScope.launch(Dispatchers.Default) {
            val overview = loadNetworkOverview()
            _uiState.value = HomeUiState(
                isLoading = false,
                permissionSummary = permissionSummary,
                activeTransportLabel = overview.activeTransportLabel,
                interfaces = overview.interfaces,
                statusMessage = overview.statusMessage,
                canContinue = permissionsGranted && overview.interfaces.isNotEmpty()
            )
        }
    }
}
