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
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.PcapAnalysis
import org.fsploit.android.domain.model.SniffedCredential
import org.fsploit.android.domain.usecase.AnalyzePcapUseCase
import org.fsploit.android.domain.usecase.LoadMitmSessionUseCase
import org.fsploit.android.domain.usecase.ReadMitmLootUseCase

data class LootUiState(
    val mode: MitmMode? = null,
    val active: Boolean = false,
    val supportsLoot: Boolean = false,
    val binaryCapture: Boolean = false,
    val artifactPath: String = "",
    val credentials: List<SniffedCredential> = emptyList(),
    val pcap: PcapAnalysis? = null,
    val keylogName: String = "",
    val stopped: Boolean = false,
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
    private val readMitmLootUseCase: ReadMitmLootUseCase,
    private val analyzePcapUseCase: AnalyzePcapUseCase,
    private val preferencesRepository: AppPreferencesRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        LootUiState(summary = resourceProvider.getString(R.string.loot_idle))
    )
    val uiState: StateFlow<LootUiState> = _uiState.asStateFlow()

    private var pollJob: Job? = null

    // The artifact file outlives a stopped session (only the session record is cleared), so we
    // remember the last sniffing capture and keep showing it after the session ends.
    private var lastMode: MitmMode? = null
    private var lastArtifactPath: String = ""

    fun startPolling() {
        if (pollJob?.isActive == true) {
            return
        }
        pollJob = viewModelScope.launch {
            while (isActive) {
                refreshOnce(force = false)
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    fun stopPolling() {
        pollJob?.cancel()
        pollJob = null
    }

    /** Persist a freshly imported keylog (path already copied into app storage by the fragment). */
    fun setKeylog(path: String, displayName: String) {
        preferencesRepository.setPcapKeylog(path, displayName)
        viewModelScope.launch { refreshOnce(force = true) }
    }

    fun clearKeylog() {
        preferencesRepository.clearPcapKeylog()
        viewModelScope.launch { refreshOnce(force = true) }
    }

    /** Manually wipe the shown loot. Stays cleared until a new sniffing session starts. */
    fun clearLoot() {
        lastMode = null
        lastArtifactPath = ""
        _uiState.value = LootUiState(
            keylogName = preferencesRepository.getPcapKeylogName(),
            summary = resourceProvider.getString(R.string.loot_idle)
        )
    }

    private suspend fun refreshOnce(force: Boolean) {
        val session = withContext(Dispatchers.Default) { loadMitmSessionUseCase() }
        val keylogName = preferencesRepository.getPcapKeylogName()

        val liveMode = session.mode
        val liveSupported = liveMode != null && liveMode in LOOT_MODES

        // Show the live session when it's a sniffing session; otherwise fall back to the last capture
        // we analyzed this app session so stopping the session doesn't blank the loot out.
        val effectiveMode: MitmMode?
        val effectiveArtifact: String
        val stopped: Boolean
        when {
            session.active && liveSupported -> {
                effectiveMode = liveMode
                effectiveArtifact = session.artifactPath
                stopped = false
                lastMode = liveMode
                lastArtifactPath = session.artifactPath
            }
            lastArtifactPath.isNotBlank() && lastMode != null -> {
                effectiveMode = lastMode
                effectiveArtifact = lastArtifactPath
                stopped = true
            }
            else -> {
                // Nothing captured yet this app session — plain idle.
                _uiState.value = _uiState.value.copy(
                    mode = liveMode,
                    active = session.active,
                    supportsLoot = liveSupported,
                    binaryCapture = false,
                    artifactPath = session.artifactPath,
                    credentials = emptyList(),
                    pcap = null,
                    keylogName = keylogName,
                    stopped = false,
                    summary = when {
                        !session.active -> resourceProvider.getString(R.string.loot_idle)
                        else -> resourceProvider.getString(R.string.loot_unsupported_mode)
                    }
                )
                return
            }
        }

        // Once stopped, the capture file is final — freeze the view and skip re-reading every poll
        // (unless forced, e.g. after importing a key to decrypt the same capture).
        if (!force && stopped && _uiState.value.stopped &&
            _uiState.value.artifactPath == effectiveArtifact
        ) {
            return
        }

        val effectiveSession = MitmSession(
            active = !stopped,
            mode = effectiveMode,
            artifactPath = effectiveArtifact
        )
        val snapshot = withContext(Dispatchers.Default) { readMitmLootUseCase(effectiveSession) }
        // SNIFFER produces a binary pcap — analyze it into a flow/HTTP/packet view rather than
        // parsing it as a credential log (which yields nothing). Pass the imported keylog so the
        // tshark engine can decrypt HTTPS when available.
        val pcap = if (effectiveMode == MitmMode.SNIFFER && snapshot.artifactPath.isNotBlank()) {
            val keylogPath = preferencesRepository.getPcapKeylogPath()
            withContext(Dispatchers.Default) { analyzePcapUseCase(snapshot.artifactPath, keylogPath) }
        } else {
            null
        }
        val baseSummary = if (pcap != null) buildPcapSummary(pcap) else buildSummary(snapshot)
        _uiState.value = _uiState.value.copy(
            mode = effectiveMode,
            active = !stopped,
            supportsLoot = true,
            binaryCapture = snapshot.binaryCapture,
            artifactPath = snapshot.artifactPath,
            credentials = snapshot.entries,
            pcap = pcap,
            keylogName = keylogName,
            stopped = stopped,
            summary = if (stopped) {
                resourceProvider.getString(R.string.loot_stopped) + "\n" + baseSummary
            } else {
                baseSummary
            }
        )
    }

    private fun buildPcapSummary(pcap: PcapAnalysis): String {
        if (!pcap.available) {
            return resourceProvider.getString(R.string.loot_pcap_unavailable, pcap.note)
        }
        return resourceProvider.getString(
            R.string.loot_pcap_summary,
            pcap.totalPackets,
            pcap.flows.size,
            pcap.http.size
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
