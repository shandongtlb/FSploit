package org.fsploit.android.feature.mitm

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.IpUtils
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.ConnectionBlockMode
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.NetworkInterfaceInfo
import org.fsploit.android.domain.usecase.BlockHostUseCase
import org.fsploit.android.domain.usecase.LoadMitmReadinessUseCase
import org.fsploit.android.domain.usecase.LoadMitmSessionUseCase
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.domain.usecase.StartMitmSessionUseCase
import org.fsploit.android.domain.usecase.StopMitmSessionUseCase
import org.fsploit.android.domain.usecase.UnblockHostUseCase
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionStateHolder

data class MitmUiState(
    val iptablesAvailable: Boolean = false,
    val tcpdumpAvailable: Boolean = false,
    val bettercapAvailable: Boolean = false,
    val mitmdumpAvailable: Boolean = false,
    val certificateStoreAccessible: Boolean = false,
    val mitmSummary: String = "",
    val selectedMitmMode: MitmMode = MitmMode.SNIFFER,
    val mitmGatewayInput: String = "",
    val mitmPrimaryInput: String = "",
    val mitmSecondaryInput: String = "",
    val mitmPayloadInput: String = "",
    val mitmSession: MitmSession = MitmSession(),
    val mitmSessionSummary: String = "",
    val isStartingMitmSession: Boolean = false,
    val mitmDiagnosticsSummary: String = "",
    val mitmDiagnosticsOutput: String = "",
    val isRunningMitmDiagnostics: Boolean = false,
    val selectedConnectionBlockMode: ConnectionBlockMode = ConnectionBlockMode.NORMAL,
    val recommendedConnectionBlockMode: ConnectionBlockMode = ConnectionBlockMode.NORMAL,
    val isConnectionBlockModeOverridden: Boolean = false,
    val connectionBlockModeSummary: String = "",
    val connectionBlockSummary: String = "",
    val isBlockingConnection: Boolean = false,
    val blockedHostAddress: String = ""
)

class MitmViewModel(
    private val resourceProvider: ResourceProvider,
    private val session: SessionStateHolder,
    private val loadMitmReadinessUseCase: LoadMitmReadinessUseCase,
    private val loadMitmSessionUseCase: LoadMitmSessionUseCase,
    private val blockHostUseCase: BlockHostUseCase,
    private val unblockHostUseCase: UnblockHostUseCase,
    private val startMitmSessionUseCase: StartMitmSessionUseCase,
    private val stopMitmSessionUseCase: StopMitmSessionUseCase,
    private val runShellCommandUseCase: RunShellCommandUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        MitmUiState(
            mitmSummary = resourceProvider.getString(R.string.mitm_pending),
            mitmSessionSummary = resourceProvider.getString(R.string.mitm_session_idle),
            mitmDiagnosticsSummary = resourceProvider.getString(R.string.mitm_diagnostics_idle),
            connectionBlockModeSummary = resourceProvider.getString(R.string.block_mode_pending),
            connectionBlockSummary = resourceProvider.getString(R.string.block_idle)
        )
    )
    val uiState: StateFlow<MitmUiState> = _uiState.asStateFlow()

    private var lastPreferredInterface: String? = null
    private var previousResolvedGateway: String = ""

    init {
        // React to shared session state: keep the gateway input echoing the resolved gateway and
        // recompute the network-mode recommendation when the interface/target/topology changes.
        viewModelScope.launch {
            session.state.collect { s -> onSessionChanged(s) }
        }
    }

    private fun onSessionChanged(s: SessionState) {
        val current = _uiState.value
        val preferredChanged = lastPreferredInterface != null && lastPreferredInterface != s.preferredInterfaceName
        lastPreferredInterface = s.preferredInterfaceName

        val gatewayInput = when {
            current.mitmGatewayInput.isBlank() -> s.resolvedGatewayAddress
            current.mitmGatewayInput == previousResolvedGateway -> s.resolvedGatewayAddress
            else -> current.mitmGatewayInput
        }
        previousResolvedGateway = s.resolvedGatewayAddress

        val keepOverride = current.isConnectionBlockModeOverridden && !preferredChanged
        val blockModeState = resolveConnectionBlockModeState(
            interfaces = s.interfaces,
            preferredInterfaceName = s.preferredInterfaceName,
            selectedHostAddress = s.selectedHostAddress,
            activeInterfaceName = s.activeInterfaceName,
            currentSelection = current.selectedConnectionBlockMode,
            keepUserSelection = keepOverride
        )

        _uiState.value = current.copy(
            mitmGatewayInput = gatewayInput,
            selectedConnectionBlockMode = blockModeState.selectedMode,
            recommendedConnectionBlockMode = blockModeState.recommendedMode,
            isConnectionBlockModeOverridden = keepOverride,
            connectionBlockModeSummary = blockModeState.summary
        )
    }

    /** Loads MITM tool readiness + the active session record. Driven from the fragment on refresh. */
    fun refresh() {
        viewModelScope.launch(Dispatchers.Default) {
            val readiness = loadMitmReadinessUseCase(session.value.shellStatus())
            val mitmSession = loadMitmSessionUseCase()
            _uiState.value = _uiState.value.copy(
                mitmSummary = readiness.summary,
                iptablesAvailable = readiness.iptablesAvailable,
                tcpdumpAvailable = readiness.tcpdumpAvailable,
                bettercapAvailable = readiness.bettercapAvailable,
                mitmdumpAvailable = readiness.mitmdumpAvailable,
                certificateStoreAccessible = readiness.certificateStoreAccessible,
                mitmSession = mitmSession,
                mitmSessionSummary = mitmSession.summary.ifBlank {
                    resourceProvider.getString(R.string.mitm_session_idle)
                }
            )
        }
    }

    fun selectMitmMode(mode: MitmMode) {
        _uiState.value = _uiState.value.copy(selectedMitmMode = mode)
    }

    fun selectConnectionBlockMode(mode: ConnectionBlockMode) {
        _uiState.value = _uiState.value.copy(
            selectedConnectionBlockMode = mode,
            isConnectionBlockModeOverridden = mode != _uiState.value.recommendedConnectionBlockMode
        )
    }

    fun updateMitmPrimaryInput(value: String) {
        _uiState.value = _uiState.value.copy(mitmPrimaryInput = value)
    }

    fun updateMitmGatewayInput(value: String) {
        _uiState.value = _uiState.value.copy(mitmGatewayInput = value.trim())
    }

    fun updateMitmSecondaryInput(value: String) {
        _uiState.value = _uiState.value.copy(mitmSecondaryInput = value)
    }

    fun updateMitmPayloadInput(value: String) {
        _uiState.value = _uiState.value.copy(mitmPayloadInput = value)
    }

    fun startMitmSession() {
        if (!ensureRootReady()) {
            return
        }

        val s = session.value
        val state = _uiState.value
        val hostAddress = s.selectedHostAddress.trim()
        if (hostAddress.isBlank()) {
            _uiState.value = state.copy(
                mitmSessionSummary = resourceProvider.getString(R.string.block_select_target_first)
            )
            return
        }
        if (
            state.selectedConnectionBlockMode == ConnectionBlockMode.NORMAL &&
            !isHostOnPreferredInterfaceSubnet(hostAddress)
        ) {
            _uiState.value = state.copy(
                mitmSessionSummary = resourceProvider.getString(
                    R.string.mitm_target_outside_interface_subnet,
                    hostAddress,
                    s.preferredInterfaceName
                )
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = state.copy(
                isStartingMitmSession = true,
                mitmSessionSummary = resourceProvider.getString(
                    R.string.mitm_session_starting,
                    resourceProvider.getString(state.selectedMitmMode.titleRes)
                )
            )

            val result = withContext(Dispatchers.Default) {
                startMitmSessionUseCase(
                    MitmLaunchRequest(
                        mode = state.selectedMitmMode,
                        networkMode = state.selectedConnectionBlockMode,
                        targetHost = hostAddress,
                        interfaceName = s.preferredInterfaceName,
                        gatewayAddress = state.mitmGatewayInput,
                        primaryValue = state.mitmPrimaryInput,
                        secondaryValue = state.mitmSecondaryInput,
                        payloadValue = state.mitmPayloadInput
                    )
                )
            }

            _uiState.value = _uiState.value.copy(
                isStartingMitmSession = false,
                mitmSession = result.session,
                mitmSessionSummary = result.summary
            )
        }
    }

    fun stopMitmSession() {
        if (!ensureRootReady()) {
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isStartingMitmSession = true,
                mitmSessionSummary = resourceProvider.getString(R.string.mitm_session_stopping)
            )

            val result = withContext(Dispatchers.Default) {
                stopMitmSessionUseCase()
            }

            _uiState.value = _uiState.value.copy(
                isStartingMitmSession = false,
                mitmSession = result.session,
                mitmSessionSummary = result.summary
            )
        }
    }

    fun runMitmDiagnostics() {
        if (!ensureRootReady()) {
            return
        }

        val s = session.value
        val state = _uiState.value
        if (s.preferredInterfaceName.isBlank()) {
            _uiState.value = state.copy(
                mitmDiagnosticsSummary = resourceProvider.getString(R.string.mitm_interface_required)
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = state.copy(
                isRunningMitmDiagnostics = true,
                mitmDiagnosticsSummary = resourceProvider.getString(R.string.mitm_diagnostics_running)
            )

            val command = buildMitmDiagnosticsCommand(s, state)
            val result = withContext(Dispatchers.Default) {
                runShellCommandUseCase(command = command, asRoot = true, timeoutMs = MITM_DIAGNOSTICS_TIMEOUT_MS)
            }
            val diagnosticsOutput = result.output.ifBlank {
                resourceProvider.getString(R.string.shell_command_no_output)
            }

            _uiState.value = _uiState.value.copy(
                isRunningMitmDiagnostics = false,
                mitmDiagnosticsSummary = buildMitmDiagnosticsSummary(
                    sessionState = s,
                    state = state,
                    shellSummary = result.summary,
                    diagnosticsOutput = diagnosticsOutput,
                    timedOut = result.timedOut
                ),
                mitmDiagnosticsOutput = diagnosticsOutput
            )
        }
    }

    fun blockSelectedHost() = performConnectionBlock(block = true)

    fun unblockSelectedHost() = performConnectionBlock(block = false)

    private fun performConnectionBlock(block: Boolean) {
        if (!ensureRootReady()) {
            return
        }

        val s = session.value
        val hostAddress = s.selectedHostAddress.trim()
        if (hostAddress.isBlank()) {
            _uiState.value = _uiState.value.copy(
                connectionBlockSummary = resourceProvider.getString(R.string.block_select_target_first)
            )
            return
        }
        if (
            block &&
            _uiState.value.selectedConnectionBlockMode == ConnectionBlockMode.NORMAL &&
            !isHostOnPreferredInterfaceSubnet(hostAddress)
        ) {
            _uiState.value = _uiState.value.copy(
                connectionBlockSummary = resourceProvider.getString(
                    R.string.mitm_target_outside_interface_subnet,
                    hostAddress,
                    s.preferredInterfaceName
                )
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isBlockingConnection = true,
                connectionBlockSummary = if (block) {
                    resourceProvider.getString(R.string.block_running, hostAddress)
                } else {
                    resourceProvider.getString(R.string.unblock_running, hostAddress)
                }
            )

            val result = withContext(Dispatchers.Default) {
                if (block) {
                    blockHostUseCase(
                        hostAddress,
                        s.preferredInterfaceName,
                        s.resolvedGatewayAddress,
                        _uiState.value.selectedConnectionBlockMode
                    )
                } else {
                    unblockHostUseCase(hostAddress)
                }
            }

            _uiState.value = _uiState.value.copy(
                isBlockingConnection = false,
                blockedHostAddress = if (block && result.success) {
                    result.targetHost
                } else if (!block && result.success && _uiState.value.blockedHostAddress == result.targetHost) {
                    ""
                } else {
                    _uiState.value.blockedHostAddress
                },
                connectionBlockSummary = result.summary
            )
        }
    }

    private fun ensureRootReady(): Boolean {
        if (session.value.rootGranted) {
            return true
        }
        _uiState.value = _uiState.value.copy(
            connectionBlockSummary = resourceProvider.getString(R.string.root_gate_blocked),
            mitmSessionSummary = resourceProvider.getString(R.string.root_gate_blocked),
            mitmDiagnosticsSummary = resourceProvider.getString(R.string.root_gate_blocked)
        )
        return false
    }

    private fun isHostOnPreferredInterfaceSubnet(hostAddress: String): Boolean {
        val s = session.value
        val preferredInterface = s.interfaces.firstOrNull { it.name == s.preferredInterfaceName } ?: return false
        return IpUtils.isHostOnInterfaceSubnet(hostAddress, preferredInterface)
    }

    private fun resolveConnectionBlockModeState(
        interfaces: List<NetworkInterfaceInfo>,
        preferredInterfaceName: String,
        selectedHostAddress: String,
        activeInterfaceName: String,
        currentSelection: ConnectionBlockMode,
        keepUserSelection: Boolean
    ): ConnectionBlockModeState {
        val recommendation = recommendConnectionBlockMode(
            interfaces = interfaces,
            preferredInterfaceName = preferredInterfaceName,
            selectedHostAddress = selectedHostAddress,
            activeInterfaceName = activeInterfaceName
        )
        return ConnectionBlockModeState(
            selectedMode = if (keepUserSelection) currentSelection else recommendation.mode,
            recommendedMode = recommendation.mode,
            summary = recommendation.summary
        )
    }

    private fun recommendConnectionBlockMode(
        interfaces: List<NetworkInterfaceInfo>,
        preferredInterfaceName: String,
        selectedHostAddress: String,
        activeInterfaceName: String
    ): ConnectionBlockModeRecommendation {
        val selectedInterface = interfaces.firstOrNull { it.name == preferredInterfaceName }
            ?: return ConnectionBlockModeRecommendation(
                mode = ConnectionBlockMode.NORMAL,
                summary = resourceProvider.getString(R.string.block_mode_unknown)
            )
        val lowerName = selectedInterface.name.lowercase()
        val looksLikeHotspotInterface = lowerName.startsWith("swlan") ||
            lowerName.startsWith("softap") ||
            lowerName.startsWith("ap")
        val hasGateway = !selectedInterface.defaultGatewayAddress.isNullOrBlank()
        val differsFromActiveInterface = activeInterfaceName.isNotBlank() &&
            !activeInterfaceName.equals(selectedInterface.name, ignoreCase = true)
        val targetMatchesSubnet = selectedHostAddress.isBlank() || IpUtils.isHostOnInterfaceSubnet(
            hostAddress = selectedHostAddress,
            networkInterface = selectedInterface
        )

        val hotspotLikely = !hasGateway && targetMatchesSubnet &&
            (looksLikeHotspotInterface || differsFromActiveInterface)

        return if (hotspotLikely) {
            ConnectionBlockModeRecommendation(
                mode = ConnectionBlockMode.HOTSPOT,
                summary = resourceProvider.getString(R.string.block_mode_detected_hotspot, selectedInterface.name)
            )
        } else {
            ConnectionBlockModeRecommendation(
                mode = ConnectionBlockMode.NORMAL,
                summary = resourceProvider.getString(
                    if (hasGateway) {
                        R.string.block_mode_detected_normal_gateway
                    } else {
                        R.string.block_mode_detected_normal_fallback
                    },
                    selectedInterface.name
                )
            )
        }
    }

    private fun buildMitmDiagnosticsCommand(s: SessionState, state: MitmUiState): String {
        val interfaceName = shellSingleQuote(s.preferredInterfaceName)
        val targetHost = s.selectedHostAddress.trim()
        val gatewayAddress = state.mitmGatewayInput.trim().ifBlank { s.resolvedGatewayAddress.trim() }
        val targetLiteral = if (targetHost.isBlank()) "" else shellSingleQuote(targetHost)
        val gatewayLiteral = if (gatewayAddress.isBlank()) "" else shellSingleQuote(gatewayAddress)
        val logPath = state.mitmSession.logPath.trim()
        val logPathLiteral = if (logPath.isBlank()) "" else shellSingleQuote(logPath)

        return buildString {
            appendLine("iface=$interfaceName")
            appendLine("target=$targetLiteral")
            appendLine("gateway=$gatewayLiteral")
            appendLine("log_path=$logPathLiteral")
            appendLine("print_section() {")
            appendLine("  printf '\\n== %s ==\\n' \"${'$'}1\"")
            appendLine("}")
            appendLine("safe_run() {")
            appendLine("  label=\"${'$'}1\"")
            appendLine("  shift")
            appendLine("  print_section \"${'$'}label\"")
            appendLine("  if \"${'$'}@\" 2>/dev/null; then")
            appendLine("    :")
            appendLine("  else")
            appendLine("    echo unavailable")
            appendLine("  fi")
            appendLine("}")
            appendLine("print_section metadata")
            appendLine("echo timestamp=${'$'}(date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date)")
            appendLine("echo interface=${'$'}iface")
            appendLine("echo selected_mode=${state.selectedConnectionBlockMode.name}")
            appendLine("echo selected_target=${if (targetHost.isBlank()) "<none>" else targetHost}")
            appendLine("echo effective_gateway=${if (gatewayAddress.isBlank()) "<none>" else gatewayAddress}")
            appendLine("echo active_session=${state.mitmSession.active}")
            appendLine("echo session_mode=${state.mitmSession.mode?.name ?: "NONE"}")
            appendLine("echo session_log=${if (logPath.isBlank()) "<none>" else logPath}")
            appendLine("safe_run 'ip addr' sh -c \"ip addr show dev \\\"${'$'}iface\\\"\"")
            appendLine("safe_run 'ip route' sh -c 'ip route show'")
            appendLine("safe_run 'ip neigh' sh -c \"ip neigh show dev \\\"${'$'}iface\\\"\"")
            appendLine("print_section /proc/net/arp")
            appendLine("if [ -r /proc/net/arp ]; then")
            appendLine("  cat /proc/net/arp")
            appendLine("else")
            appendLine("  echo unavailable")
            appendLine("fi")
            appendLine("print_section target_arp")
            appendLine("if [ -n \"${'$'}target\" ]; then")
            appendLine("  grep -F \"${'$'}target\" /proc/net/arp 2>/dev/null || echo missing")
            appendLine("else")
            appendLine("  echo no_target_selected")
            appendLine("fi")
            appendLine("print_section gateway_arp")
            appendLine("if [ -n \"${'$'}gateway\" ]; then")
            appendLine("  grep -F \"${'$'}gateway\" /proc/net/arp 2>/dev/null || echo missing")
            appendLine("else")
            appendLine("  echo no_gateway_selected")
            appendLine("fi")
            appendLine("safe_run 'iptables filter' sh -c 'iptables -S FORWARD'")
            appendLine("safe_run 'iptables nat' sh -c 'iptables -t nat -S'")
            appendLine("print_section bettercap_processes")
            appendLine("ps 2>/dev/null | grep -E 'bettercap|mitmdump|tcpdump' | grep -v grep || echo none")
            appendLine("print_section recent_log")
            appendLine("if [ -n \"${'$'}log_path\" ] && [ -r \"${'$'}log_path\" ]; then")
            appendLine("  tail -n 40 \"${'$'}log_path\"")
            appendLine("else")
            appendLine("  echo unavailable")
            appendLine("fi")
        }
    }

    private fun buildMitmDiagnosticsSummary(
        sessionState: SessionState,
        state: MitmUiState,
        shellSummary: String,
        diagnosticsOutput: String,
        timedOut: Boolean
    ): String {
        if (timedOut) {
            return resourceProvider.getString(R.string.mitm_diagnostics_timed_out)
        }

        val findings = mutableListOf<String>()
        val gatewayAddress = state.mitmGatewayInput.trim().ifBlank { sessionState.resolvedGatewayAddress.trim() }

        if (
            state.selectedConnectionBlockMode == ConnectionBlockMode.NORMAL &&
            gatewayAddress.isBlank()
        ) {
            findings += resourceProvider.getString(R.string.mitm_diagnostics_hint_gateway_missing)
        }
        if (diagnosticsOutput.contains("Could not detect gateway", ignoreCase = true)) {
            findings += resourceProvider.getString(R.string.mitm_diagnostics_hint_bettercap_gateway)
        }
        if (diagnosticsOutput.contains("ARP spoofing mechanisms", ignoreCase = true)) {
            findings += resourceProvider.getString(R.string.mitm_diagnostics_hint_router_protection)
        }
        if (sectionContainsLine(diagnosticsOutput, "target_arp", "missing")) {
            findings += resourceProvider.getString(R.string.mitm_diagnostics_hint_target_arp_missing)
        }
        if (gatewayAddress.isNotBlank() && sectionContainsLine(diagnosticsOutput, "gateway_arp", "missing")) {
            findings += resourceProvider.getString(R.string.mitm_diagnostics_hint_gateway_arp_missing)
        }
        if (sectionContainsLine(diagnosticsOutput, "bettercap_processes", "none")) {
            findings += resourceProvider.getString(R.string.mitm_diagnostics_hint_process_missing)
        }

        val conclusion = when {
            findings.isNotEmpty() -> findings.joinToString(" ")
            state.selectedConnectionBlockMode == ConnectionBlockMode.HOTSPOT ->
                resourceProvider.getString(R.string.mitm_diagnostics_hint_hotspot_baseline)
            else -> resourceProvider.getString(R.string.mitm_diagnostics_hint_no_obvious_failure)
        }

        return "$shellSummary $conclusion".trim()
    }

    private fun shellSingleQuote(value: String): String {
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }

    private fun sectionContainsLine(output: String, sectionName: String, expectedLine: String): Boolean {
        val marker = "== $sectionName =="
        val startIndex = output.indexOf(marker, ignoreCase = true)
        if (startIndex < 0) {
            return false
        }
        val sectionBodyStart = output.indexOf('\n', startIndex).let { index ->
            if (index >= 0) index + 1 else return false
        }
        val nextMarkerIndex = output.indexOf("\n== ", sectionBodyStart)
        val sectionBody = if (nextMarkerIndex >= 0) {
            output.substring(sectionBodyStart, nextMarkerIndex)
        } else {
            output.substring(sectionBodyStart)
        }
        return sectionBody.lineSequence().any { it.trim().equals(expectedLine, ignoreCase = true) }
    }

    private data class ConnectionBlockModeRecommendation(
        val mode: ConnectionBlockMode,
        val summary: String
    )

    private data class ConnectionBlockModeState(
        val selectedMode: ConnectionBlockMode,
        val recommendedMode: ConnectionBlockMode,
        val summary: String
    )

    companion object {
        private const val MITM_DIAGNOSTICS_TIMEOUT_MS = 8000L
    }
}
