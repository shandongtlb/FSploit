package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.data.shell.ShellRepository
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmToolchainConfig
import org.fsploit.android.domain.model.ShellStatus

class ToolchainProbe(
    private val resourceProvider: ResourceProvider,
    private val shellRepository: ShellRepository,
    private val preferencesRepository: AppPreferencesRepository
) {
    fun loadReadiness(shellStatus: ShellStatus): MitmReadiness {
        if (!shellStatus.rootGranted) {
            return MitmReadiness(
                iptablesAvailable = false,
                tcpdumpAvailable = false,
                arpspoofAvailable = false,
                ettercapAvailable = false,
                mitmdumpAvailable = false,
                certificateStoreAccessible = false,
                summary = resourceProvider.getString(R.string.mitm_root_required)
            )
        }

        val config = preferencesRepository.getMitmToolchainConfig()
        val iptablesAvailable = executableExists("iptables") ||
            executableExists("iptables-legacy") ||
            executableExists("iptables-nft")
        val tcpdumpAvailable = executableExists(config.tcpdumpPath)
        val arpspoofAvailable = executableExists(config.arpspoofPath)
        val ettercapAvailable = executableExists(config.ettercapPath)
        val mitmdumpAvailable = executableExists(config.mitmdumpPath)
        val certificateStoreAccessible = directoryAccessible("/system/etc/security/cacerts") ||
            directoryAccessible("/apex/com.android.conscrypt/cacerts")

        val summary = when {
            !iptablesAvailable -> resourceProvider.getString(R.string.mitm_missing_iptables)
            !arpspoofAvailable -> resourceProvider.getString(R.string.mitm_missing_arpspoof)
            !tcpdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_tcpdump)
            !ettercapAvailable -> resourceProvider.getString(R.string.mitm_missing_ettercap)
            !mitmdumpAvailable -> resourceProvider.getString(R.string.mitm_missing_mitmdump)
            !certificateStoreAccessible -> resourceProvider.getString(R.string.mitm_missing_ca_store)
            else -> resourceProvider.getString(R.string.mitm_ready)
        }

        return MitmReadiness(
            iptablesAvailable = iptablesAvailable,
            tcpdumpAvailable = tcpdumpAvailable,
            arpspoofAvailable = arpspoofAvailable,
            ettercapAvailable = ettercapAvailable,
            mitmdumpAvailable = mitmdumpAvailable,
            certificateStoreAccessible = certificateStoreAccessible,
            summary = summary
        )
    }

    fun loadConfig(): MitmToolchainConfig = preferencesRepository.getMitmToolchainConfig()

    private fun executableExists(configuredValue: String): Boolean {
        val value = configuredValue.trim()
        if (value.isEmpty()) {
            return false
        }
        val command = if (value.contains('/')) {
            "[ -x ${shellQuote(value)} ] && echo ok"
        } else {
            "command -v $value"
        }
        val result = shellRepository.execute(
            command = command,
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
        return result.exitCode == 0 && result.output.isNotBlank()
    }

    private fun directoryAccessible(path: String): Boolean {
        val result = shellRepository.execute(
            command = "[ -d ${shellQuote(path)} ] && echo ok",
            asRoot = true,
            timeoutMs = PROBE_TIMEOUT_MS
        )
        return result.exitCode == 0 && result.output.contains("ok")
    }

    private fun shellQuote(value: String): String {
        return "'" + value.replace("'", "'\"'\"'") + "'"
    }

    companion object {
        private const val PROBE_TIMEOUT_MS = 2000L
    }
}
