package org.fsploit.android.core

import androidx.annotation.StringRes
import org.fsploit.android.R

enum class ShellTaskPreset(
    val command: String,
    val runAsRoot: Boolean,
    @StringRes val titleRes: Int,
    @StringRes val descriptionRes: Int
) {
    NETWORK_INTERFACES(
        command = "ip addr show",
        runAsRoot = false,
        titleRes = R.string.shell_task_network_interfaces,
        descriptionRes = R.string.shell_task_network_interfaces_desc
    ),
    ARP_NEIGHBORS(
        command = "ip neigh show",
        runAsRoot = false,
        titleRes = R.string.shell_task_arp_neighbors,
        descriptionRes = R.string.shell_task_arp_neighbors_desc
    ),
    IPTABLES_RULES(
        command = "iptables -L -n",
        runAsRoot = true,
        titleRes = R.string.shell_task_iptables_rules,
        descriptionRes = R.string.shell_task_iptables_rules_desc
    ),
    TCPDUMP_VERSION(
        command = "tcpdump --version",
        runAsRoot = false,
        titleRes = R.string.shell_task_tcpdump_version,
        descriptionRes = R.string.shell_task_tcpdump_version_desc
    )
}
