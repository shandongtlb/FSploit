package org.fsploit.android.core

import android.content.Context

/**
 * Resolves a MAC address to its vendor by IEEE OUI (the first 24 bits / 3 octets).
 *
 * The lookup table is bundled as the `oui_prefixes.csv` asset (`AABBCC,Vendor` per line,
 * derived from the Wireshark `manuf` database). It is parsed lazily on first use and cached
 * for the process lifetime, so a sweep that never reads a MAC pays nothing.
 */
class OuiLookup(
    context: Context
) {
    private val appContext = context.applicationContext

    private val table: Map<String, String> by lazy { loadTable() }

    /** Returns the vendor name for [macAddress], or null if the OUI is unknown/unparseable. */
    fun vendorFor(macAddress: String?): String? {
        val prefix = ouiPrefix(macAddress) ?: return null
        return table[prefix]
    }

    private fun ouiPrefix(macAddress: String?): String? {
        if (macAddress.isNullOrBlank()) {
            return null
        }
        val hex = StringBuilder(6)
        for (ch in macAddress) {
            if (ch == ':' || ch == '-' || ch == '.') {
                continue
            }
            if (!isHexDigit(ch)) {
                return null
            }
            hex.append(ch.uppercaseChar())
            if (hex.length == 6) {
                break
            }
        }
        return if (hex.length == 6) hex.toString() else null
    }

    private fun isHexDigit(ch: Char): Boolean {
        return ch in '0'..'9' || ch in 'a'..'f' || ch in 'A'..'F'
    }

    private fun loadTable(): Map<String, String> {
        val result = HashMap<String, String>(48_000)
        try {
            appContext.assets.open(ASSET_NAME).bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val comma = line.indexOf(',')
                    if (comma == 6) {
                        result[line.substring(0, 6)] = line.substring(comma + 1)
                    }
                }
            }
        } catch (_: Exception) {
            // Missing/corrupt asset just means no vendor enrichment; callers handle null.
        }
        return result
    }

    companion object {
        private const val ASSET_NAME = "oui_prefixes.csv"
    }
}
