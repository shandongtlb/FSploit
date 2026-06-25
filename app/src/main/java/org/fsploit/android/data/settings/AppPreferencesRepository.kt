package org.fsploit.android.data.settings

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.fsploit.android.domain.model.MsfRpcConfig
import org.fsploit.android.domain.model.MitmToolchainConfig
import org.fsploit.android.domain.model.PortScanConfig

class AppPreferencesRepository(
    context: Context
) {
    private val preferences: SharedPreferences = buildPreferences(context.applicationContext)

    /**
     * Prefer an AES-256 [EncryptedSharedPreferences] store so the saved RPC password is not left as
     * plaintext on disk. The Android keystore can fail on unusual ROMs or after a key corruption, so
     * we degrade gracefully to a plain private store rather than crash the app on launch.
     */
    private fun buildPreferences(context: Context): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            val secure = EncryptedSharedPreferences.create(
                context,
                SECURE_PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
            migrateLegacyIfNeeded(context, secure)
            secure
        } catch (_: Exception) {
            context.getSharedPreferences(LEGACY_PREFS_NAME, Context.MODE_PRIVATE)
        }
    }

    /** One-time copy of any previously saved plaintext settings into the encrypted store. */
    private fun migrateLegacyIfNeeded(context: Context, secure: SharedPreferences) {
        if (secure.getBoolean(KEY_MIGRATED, false)) {
            return
        }
        val legacy = context.getSharedPreferences(LEGACY_PREFS_NAME, Context.MODE_PRIVATE)
        val editor = secure.edit()
        for ((key, value) in legacy.all) {
            when (value) {
                is String -> editor.putString(key, value)
                is Int -> editor.putInt(key, value)
                is Boolean -> editor.putBoolean(key, value)
                is Long -> editor.putLong(key, value)
                is Float -> editor.putFloat(key, value)
            }
        }
        editor.putBoolean(KEY_MIGRATED, true).apply()
        legacy.edit().clear().apply()
    }

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

    /** Imported TLS keylog (SSLKEYLOGFILE) used to decrypt HTTPS in the pcap viewer; "" if none. */
    fun getPcapKeylogPath(): String = preferences.getString(KEY_PCAP_KEYLOG_PATH, "").orEmpty()

    fun getPcapKeylogName(): String = preferences.getString(KEY_PCAP_KEYLOG_NAME, "").orEmpty()

    fun setPcapKeylog(path: String, displayName: String) {
        preferences.edit()
            .putString(KEY_PCAP_KEYLOG_PATH, path.trim())
            .putString(KEY_PCAP_KEYLOG_NAME, displayName.trim())
            .apply()
    }

    fun clearPcapKeylog() {
        preferences.edit()
            .remove(KEY_PCAP_KEYLOG_PATH)
            .remove(KEY_PCAP_KEYLOG_NAME)
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
        private const val SECURE_PREFS_NAME = "fsploit_secure_preferences"
        private const val LEGACY_PREFS_NAME = "fsploit_preferences"
        private const val KEY_MIGRATED = "prefs_migrated_to_encrypted"
        private const val KEY_PREFERRED_INTERFACE = "preferred_interface"
        private const val KEY_PORT_SPEC = "port_spec"
        private const val KEY_CONNECT_TIMEOUT_MS = "connect_timeout_ms"
        private const val KEY_PARALLELISM = "parallelism"
        private const val KEY_MITM_BETTERCAP_PATH = "mitm_bettercap_path"
        private const val KEY_MITM_TCPDUMP_PATH = "mitm_tcpdump_path"
        private const val KEY_MITM_MITMDUMP_PATH = "mitm_mitmdump_path"
        private const val KEY_MITM_HTTP_REDIRECT_PORT = "mitm_http_redirect_port"
        private const val KEY_PCAP_KEYLOG_PATH = "pcap_keylog_path"
        private const val KEY_PCAP_KEYLOG_NAME = "pcap_keylog_name"
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
