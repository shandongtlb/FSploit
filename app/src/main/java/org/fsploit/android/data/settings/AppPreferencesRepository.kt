package org.fsploit.android.data.settings

import android.content.Context
import org.fsploit.android.domain.model.MsfRpcConfig
import org.fsploit.android.domain.model.MitmToolchainConfig
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

    fun getMitmToolchainConfig(): MitmToolchainConfig {
        return MitmToolchainConfig(
            bettercapPath = preferences.getString(KEY_MITM_BETTERCAP_PATH, DEFAULT_BETTERCAP_PATH).orEmpty(),
            tcpdumpPath = preferences.getString(KEY_MITM_TCPDUMP_PATH, DEFAULT_TCPDUMP_PATH).orEmpty(),
            mitmdumpPath = preferences.getString(KEY_MITM_MITMDUMP_PATH, DEFAULT_MITMDUMP_PATH).orEmpty(),
            httpRedirectPort = preferences.getInt(KEY_MITM_HTTP_REDIRECT_PORT, DEFAULT_MITM_HTTP_REDIRECT_PORT)
        )
    }

    fun setMitmToolchainConfig(config: MitmToolchainConfig) {
        preferences.edit()
            .putString(KEY_MITM_BETTERCAP_PATH, config.bettercapPath.trim())
            .putString(KEY_MITM_TCPDUMP_PATH, config.tcpdumpPath.trim())
            .putString(KEY_MITM_MITMDUMP_PATH, config.mitmdumpPath.trim())
            .putInt(KEY_MITM_HTTP_REDIRECT_PORT, config.httpRedirectPort)
            .apply()
    }

    fun getMsfRpcConfig(): MsfRpcConfig {
        return MsfRpcConfig(
            host = preferences.getString(KEY_MSF_RPC_HOST, DEFAULT_MSF_RPC_HOST).orEmpty(),
            port = preferences.getInt(KEY_MSF_RPC_PORT, DEFAULT_MSF_RPC_PORT),
            username = preferences.getString(KEY_MSF_RPC_USERNAME, DEFAULT_MSF_RPC_USERNAME).orEmpty(),
            password = preferences.getString(KEY_MSF_RPC_PASSWORD, DEFAULT_MSF_RPC_PASSWORD).orEmpty(),
            useSsl = preferences.getBoolean(KEY_MSF_RPC_USE_SSL, DEFAULT_MSF_RPC_USE_SSL),
            launchCommand = preferences.getString(KEY_MSF_RPC_LAUNCH_COMMAND, DEFAULT_MSF_RPC_LAUNCH_COMMAND).orEmpty()
        )
    }

    fun setMsfRpcConfig(config: MsfRpcConfig) {
        preferences.edit()
            .putString(KEY_MSF_RPC_HOST, config.host.trim())
            .putInt(KEY_MSF_RPC_PORT, config.port)
            .putString(KEY_MSF_RPC_USERNAME, config.username.trim())
            .putString(KEY_MSF_RPC_PASSWORD, config.password)
            .putBoolean(KEY_MSF_RPC_USE_SSL, config.useSsl)
            .putString(KEY_MSF_RPC_LAUNCH_COMMAND, config.launchCommand.trim())
            .apply()
    }

    companion object {
        private const val KEY_PREFERRED_INTERFACE = "preferred_interface"
        private const val KEY_PORT_SPEC = "port_spec"
        private const val KEY_CONNECT_TIMEOUT_MS = "connect_timeout_ms"
        private const val KEY_PARALLELISM = "parallelism"
        private const val KEY_MITM_BETTERCAP_PATH = "mitm_bettercap_path"
        private const val KEY_MITM_TCPDUMP_PATH = "mitm_tcpdump_path"
        private const val KEY_MITM_MITMDUMP_PATH = "mitm_mitmdump_path"
        private const val KEY_MITM_HTTP_REDIRECT_PORT = "mitm_http_redirect_port"
        private const val KEY_MSF_RPC_HOST = "msf_rpc_host"
        private const val KEY_MSF_RPC_PORT = "msf_rpc_port"
        private const val KEY_MSF_RPC_USERNAME = "msf_rpc_username"
        private const val KEY_MSF_RPC_PASSWORD = "msf_rpc_password"
        private const val KEY_MSF_RPC_USE_SSL = "msf_rpc_use_ssl"
        private const val KEY_MSF_RPC_LAUNCH_COMMAND = "msf_rpc_launch_command"
        private const val DEFAULT_PORT_SPEC =
            "21-23,53,80,110,139,143,443,445,3306,3389,5432,5900,8080,8443"
        private const val DEFAULT_CONNECT_TIMEOUT_MS = 250
        private const val DEFAULT_PARALLELISM = 16
        private const val DEFAULT_BETTERCAP_PATH = "bettercap"
        private const val DEFAULT_TCPDUMP_PATH = "tcpdump"
        private const val DEFAULT_MITMDUMP_PATH = "mitmdump"
        private const val DEFAULT_MITM_HTTP_REDIRECT_PORT = 18080
        private const val DEFAULT_MSF_RPC_HOST = "127.0.0.1"
        private const val DEFAULT_MSF_RPC_PORT = 55552
        private const val DEFAULT_MSF_RPC_USERNAME = "msf"
        private const val DEFAULT_MSF_RPC_PASSWORD = "msf"
        private const val DEFAULT_MSF_RPC_USE_SSL = false
        private const val DEFAULT_MSF_RPC_LAUNCH_COMMAND = ""
    }
}
