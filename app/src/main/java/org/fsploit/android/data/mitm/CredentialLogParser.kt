package org.fsploit.android.data.mitm

import org.fsploit.android.domain.model.SniffedCredential
import org.json.JSONObject

/**
 * Best-effort parser for MITM loot artifacts. The real bettercap event-stream format
 * varies by protocol and version, so parsing is deliberately lenient: every kept line
 * becomes an entry with its original text in [SniffedCredential.raw], and structured
 * fields (user/pass/protocol) are filled in only when they can be confidently matched.
 */
class CredentialLogParser {

    /** Parse a bettercap `net.sniff` credential log (stdout stream redirected to a file). */
    fun parseCredentialsLog(content: String): List<SniffedCredential> {
        return content.lineSequence()
            .map { stripAnsi(it).trim() }
            .filter { it.isNotEmpty() && isInteresting(it) }
            .map { parseLine(it) }
            .toList()
    }

    /** Parse a mitmdump `cookies.jsonl` artifact (one JSON object per line). */
    fun parseCookiesJsonl(content: String): List<SniffedCredential> {
        return content.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { line ->
                try {
                    val obj = JSONObject(line)
                    SniffedCredential(
                        protocol = "cookie",
                        source = obj.firstNonBlank("host", "domain", "url"),
                        username = obj.firstNonBlank("name", "key"),
                        password = obj.firstNonBlank("value"),
                        raw = line
                    )
                } catch (_: Exception) {
                    SniffedCredential(protocol = "cookie", raw = line)
                }
            }
            .toList()
    }

    private fun isInteresting(line: String): Boolean {
        val lower = line.lowercase()
        if (CRED_KEYWORDS.any { lower.contains(it) }) {
            return true
        }
        return SNIFF_TAG.containsMatchIn(line)
    }

    private fun parseLine(line: String): SniffedCredential {
        val timestamp = TIMESTAMP.find(line)?.value?.trim('[', ']', ' ').orEmpty()
        val protocol = SNIFF_TAG.find(line)?.groupValues?.getOrNull(1)?.substringAfterLast('.').orEmpty()
        val username = USER.find(line)?.groupValues?.getOrNull(1)?.trim()?.trimEnd(',', ';', '&', '"').orEmpty()
        val password = PASS.find(line)?.groupValues?.getOrNull(1)?.trim()?.trimEnd(',', ';', '&', '"').orEmpty()
        return SniffedCredential(
            timestamp = timestamp,
            protocol = protocol,
            source = line,
            username = username,
            password = password,
            raw = line
        )
    }

    private fun stripAnsi(value: String): String = ANSI.replace(value, "")

    private fun JSONObject.firstNonBlank(vararg keys: String): String {
        for (key in keys) {
            val value = optString(key, "")
            if (value.isNotBlank()) {
                return value
            }
        }
        return ""
    }

    companion object {
        private val ANSI = Regex("\\[[;\\d]*m")
        private val TIMESTAMP = Regex("^\\[?\\d{1,2}:\\d{2}:\\d{2}]?")
        private val SNIFF_TAG = Regex("\\[(net\\.sniff[a-zA-Z0-9._-]*)]")
        private val USER = Regex("(?i)\\b(?:user(?:name)?|login|email)\\b\\s*[=:]\\s*(\\S+)")
        private val PASS = Regex("(?i)\\b(?:pass(?:word)?|pwd)\\b\\s*[=:]\\s*(\\S+)")
        private val CRED_KEYWORDS = listOf(
            "password", "passwd", "pwd=", "user=", "username", "login",
            "authorization", "credential", "cookie"
        )
    }
}
