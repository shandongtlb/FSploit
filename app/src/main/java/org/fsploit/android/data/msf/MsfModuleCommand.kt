package org.fsploit.android.data.msf

/**
 * Pure builder for the `multi/handler` `module.execute` options map. Side-effect free.
 */
internal object MsfModuleCommand {

    /** Options for a `multi/handler` job — the reverse listener that catches a payload's callback. */
    fun buildHandlerOptions(payload: String, lhost: String, lport: String): Map<String, Any> {
        val options = LinkedHashMap<String, Any>()
        if (payload.isNotBlank()) options["PAYLOAD"] = payload.trim()
        if (lhost.isNotBlank()) options["LHOST"] = lhost.trim()
        lport.trim().toIntOrNull()?.let { options["LPORT"] = it }
        // Keep the handler alive for more than one catch.
        options["ExitOnSession"] = false
        return options
    }
}
