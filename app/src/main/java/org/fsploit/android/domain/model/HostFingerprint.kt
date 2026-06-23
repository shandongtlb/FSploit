package org.fsploit.android.domain.model

/** Coarse OS family guessed primarily from the reply TTL, refined by port signatures. */
enum class OsFamily {
    LINUX_UNIX,
    WINDOWS,
    NETWORK_DEVICE,
    APPLE,
    UNKNOWN
}

/** A service/role signal inferred from a distinctive open port. */
enum class DeviceRole {
    REMOTE_DESKTOP,
    SMB_SHARE,
    SSH,
    IP_CAMERA,
    PRINTER,
    NAS,
    DATABASE,
    IOT_TELNET,
    ROUTER_DNS,
    APPLE_DEVICE,
    WEB_SERVER
}

/** Best-effort host fingerprint derived from open ports + reply TTL. Purely heuristic. */
data class HostFingerprint(
    val osFamily: OsFamily = OsFamily.UNKNOWN,
    val ttl: Int? = null,
    val roles: List<DeviceRole> = emptyList()
)
