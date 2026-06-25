package org.fsploit.android.feature.session

import org.fsploit.android.domain.model.HostScanResult
import org.fsploit.android.domain.model.NetworkInterfaceInfo
import org.fsploit.android.domain.model.ShellStatus

/**
 * Cross-screen shared state — the single source of truth for everything that more than one
 * feature screen reads or writes (network interfaces, root/shell status, the preferred
 * interface and its gateway, the currently selected target host, and host-sweep results).
 *
 * Owned by [SessionStateHolder]; orchestrated by [SessionViewModel]; observed reactively by the
 * per-feature ViewModels.
 */
data class SessionState(
    val isLoading: Boolean = true,
    val permissionSummary: String = "",
    val activeTransportLabel: String = "",
    val activeInterfaceName: String = "",
    val interfaces: List<NetworkInterfaceInfo> = emptyList(),
    val statusMessage: String = "",
    val canContinue: Boolean = false,
    val shellAvailable: Boolean = false,
    val suAvailable: Boolean = false,
    val rootGranted: Boolean = false,
    val shellSummary: String = "",
    val rootGateSummary: String = "",
    val preferredInterfaceName: String = "",
    val resolvedGatewayAddress: String = "",
    val responsiveTargetResults: List<HostScanResult> = emptyList(),
    val responsiveHosts: List<String> = emptyList(),
    val selectedHostAddress: String = "",
    val scanSummary: String = "",
    val scannedHostCount: Int = 0,
    val isScanning: Boolean = false
) {
    /** Reconstructs the [ShellStatus] snapshot so feature ViewModels can derive their own readiness. */
    fun shellStatus(): ShellStatus = ShellStatus(
        shellAvailable = shellAvailable,
        suAvailable = suAvailable,
        rootGranted = rootGranted,
        summary = shellSummary
    )
}
