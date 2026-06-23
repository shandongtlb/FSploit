package org.fsploit.android.data.msf

/**
 * Pure builders for the attack flows: composing the editable `msfvenom` command line and the
 * `module.execute` options map. Kept side-effect free so they are trivially unit-testable.
 */
internal object MsfModuleCommand {

    /**
     * Builds an `msfvenom` command wrapped for the NetHunter chroot. Blank `-f`/`-o`/`LHOST`/`LPORT`
     * segments are omitted so a half-filled form still produces a runnable-looking command the user
     * can finish editing. The result is intentionally editable downstream — chroot paths vary.
     */
    fun composeVenomCommand(
        payload: String,
        lhost: String,
        lport: String,
        format: String,
        output: String
    ): String {
        val inner = buildString {
            append("msfvenom")
            append(" -p ").append(payload.trim().ifBlank { "<PAYLOAD>" })
            if (lhost.isNotBlank()) append(" LHOST=").append(lhost.trim())
            if (lport.isNotBlank()) append(" LPORT=").append(lport.trim())
            if (format.isNotBlank()) append(" -f ").append(format.trim())
            if (output.isNotBlank()) append(" -o ").append(output.trim())
        }
        return "nh -r \"$inner\""
    }

    /**
     * Assembles the `module.execute` options for an exploit. Blank fields are dropped (so MSF falls
     * back to module defaults) and ports are sent as integers, which the RPC packer requires.
     */
    fun buildExploitOptions(
        rhosts: String,
        rport: String,
        payload: String,
        lhost: String,
        lport: String
    ): Map<String, Any> {
        val options = LinkedHashMap<String, Any>()
        if (rhosts.isNotBlank()) options["RHOSTS"] = rhosts.trim()
        rport.trim().toIntOrNull()?.let { options["RPORT"] = it }
        if (payload.isNotBlank()) options["PAYLOAD"] = payload.trim()
        if (lhost.isNotBlank()) options["LHOST"] = lhost.trim()
        lport.trim().toIntOrNull()?.let { options["LPORT"] = it }
        return options
    }

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
