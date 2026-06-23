package org.fsploit.android.data.msf

/**
 * Routing helper for the two console transports MSF exposes per session: meterpreter sessions use
 * `session.meterpreter_*` RPC methods, everything else (command shells) uses `session.shell_*`.
 */
internal object MsfSessionType {
    fun isMeterpreter(type: String): Boolean =
        type.trim().lowercase().contains("meterpreter")
}
