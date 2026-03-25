package org.fsploit.android.data.settings

import android.content.Context
import org.fsploit.android.domain.model.PortScanConfig

class AppPreferencesRepository(
    context: Context
) {
    private val preferences = context.applicationContext.getSharedPreferences(
        "fsploit_preferences",
        Context.MODE_PRIVATE
    )

    fun getPreferredInterfaceName(): String = preferences.getString(KEY_PREFERRED_INTERFACE, "").orEmpty()

    fun setPreferredInterfaceName(interfaceName: String) {
        preferences.edit().putString(KEY_PREFERRED_INTERFACE, interfaceName.trim()).apply()
    }

    fun getPortScanConfig(): PortScanConfig {
        return PortScanConfig(
            portSpec = preferences.getString(KEY_PORT_SPEC, DEFAULT_PORT_SPEC).orEmpty(),
            connectTimeoutMs = preferences.getInt(KEY_CONNECT_TIMEOUT_MS, DEFAULT_CONNECT_TIMEOUT_MS),
            parallelism = preferences.getInt(KEY_PARALLELISM, DEFAULT_PARALLELISM)
        )
    }

    fun setPortScanConfig(config: PortScanConfig) {
        preferences.edit()
            .putString(KEY_PORT_SPEC, config.portSpec.trim())
            .putInt(KEY_CONNECT_TIMEOUT_MS, config.connectTimeoutMs)
            .putInt(KEY_PARALLELISM, config.parallelism)
            .apply()
    }

    companion object {
        private const val KEY_PREFERRED_INTERFACE = "preferred_interface"
        private const val KEY_PORT_SPEC = "port_spec"
        private const val KEY_CONNECT_TIMEOUT_MS = "connect_timeout_ms"
        private const val KEY_PARALLELISM = "parallelism"
        private const val DEFAULT_PORT_SPEC =
            "21-23,53,80,110,139,143,443,445,3306,3389,5432,5900,8080,8443"
        private const val DEFAULT_CONNECT_TIMEOUT_MS = 250
        private const val DEFAULT_PARALLELISM = 16
    }
}
