package org.fsploit.android.feature.loot

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.SniffedCredential
import org.fsploit.android.domain.usecase.LoadMitmSessionUseCase
import org.fsploit.android.domain.usecase.ReadMitmLootUseCase

data class LootUiState(
    val mode: MitmMode? = null,
    val active: Boolean = false,
    val supportsLoot: Boolean = false,
    val binaryCapture: Boolean = false,
    val artifactPath: String = "",
    val credentials: List<SniffedCredential> = emptyList(),
    val summary: String = ""
)

/**
 * Surfaces credentials/cookies captured by the active MITM session. While the fragment is
 * resumed it polls the session's loot artifact (read back as root); it never tails so it
 * cannot block the synchronous shell. Only sniffing modes produce parseable loot.
 */
class LootViewModel(
    private val resourceProvider: ResourceProvider,
    private val loadMitmSessionUseCase: LoadMitmSessionUseCase,
    private val readMitmLootUseCase: ReadMitmLootUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        LootUiState(summary = resourceProvider.getString(R.string.loot_idle))
    )
    val uiState: StateFlow<LootUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null

    fun startPolling() {
        if (pollJob?.isActive == true) {
            return
        }
        pollJob = viewModelScope.launch {
            while (isActive) {
                refreshOnce()
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    private suspend fun refreshOnce() {
        val session = withContext(Dispatchers.Default) { loadMitmSessionUseCase() }
        val mode = session.mode
        val supportsLoot = mode != null && mode in LOOT_MODES

        if (!session.active || !supportsLoot) {
            _uiState.value = _uiState.value.copy(
                mode = mode,
                active = session.active,
                supportsLoot = supportsLoot,
                binaryCapture = false,
                artifactPath = session.artifactPath,
                credentials = emptyList(),
                summary = when {
                    !session.active -> resourceProvider.getString(R.string.loot_idle)
                    else -> resourceProvider.getString(R.string.loot_unsupported_mode)
                }
            )
            return
        }

        val snapshot = withContext(Dispatchers.Default) { readMitmLootUseCase(session) }
        _uiState.value = _uiState.value.copy(
            mode = mode,
            active = true,
            supportsLoot = true,
            binaryCapture = snapshot.binaryCapture,
            artifactPath = snapshot.artifactPath,
            credentials = snapshot.entries,
            summary = buildSummary(snapshot)
        )
    }

    private fun buildSummary(snapshot: org.fsploit.android.domain.model.MitmLootSnapshot): String {
        return when {
            snapshot.binaryCapture ->
                resourceProvider.getString(R.string.loot_binary_capture, snapshot.artifactPath)
            !snapshot.available ->
                resourceProvider.getString(R.string.loot_unavailable)
            snapshot.entries.isNotEmpty() ->
                resourceProvider.getString(R.string.loot_count, snapshot.entries.size)
            else ->
                resourceProvider.getString(R.string.loot_empty_active, snapshot.rawLineCount)
        }
    }

    override fun onCleared() {
        super.onCleared()
        stopPolling()
    }

    companion object {
        private const val POLL_INTERVAL_MS = 2000L
        private val LOOT_MODES = setOf(
            MitmMode.PASSWORD_SNIFFER,
            MitmMode.SESSION_HIJACK,
            MitmMode.SNIFFER
        )
    }
}
