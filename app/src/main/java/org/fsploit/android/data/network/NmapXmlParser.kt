package org.fsploit.android.data.network

import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.StringReader

/** A single OS guess from nmap's `<osmatch>`. */
data class NmapOsMatch(
    val name: String,
    val accuracy: Int
)

/** One `<port>` entry from nmap XML. */
data class NmapPort(
    val portId: Int,
    val protocol: String,
    val state: String,
    val service: String?,
    val product: String?,
    val version: String?,
    val extraInfo: String?
)

/** One `<host>` entry from nmap XML. */
data class NmapHost(
    val ipv4: String?,
    val mac: String?,
    val vendor: String?,
    val status: String?,
    val hostnames: List<String>,
    val osMatches: List<NmapOsMatch>,
    val ports: List<NmapPort>
) {
    val isUp: Boolean get() = status == null || status == "up"
}

/**
 * Parses nmap `-oX -` output with the platform [XmlPullParser] (no third-party dependency).
 * Tolerant by design: nmap streams partial XML on timeout/cancel, so a parse error returns
 * whatever hosts were already fully read rather than throwing.
 */
object NmapXmlParser {

    fun parse(xml: String): List<NmapHost> {
        if (xml.isBlank()) {
            return emptyList()
        }
        val hosts = mutableListOf<NmapHost>()

        val parser = XmlPullParserFactory.newInstance().newPullParser().apply {
            setInput(StringReader(xml))
        }

        var ipv4: String? = null
        var mac: String? = null
        var vendor: String? = null
        var status: String? = null
        var hostnames = mutableListOf<String>()
        var osMatches = mutableListOf<NmapOsMatch>()
        var ports = mutableListOf<NmapPort>()

        // Per-port scratch state, populated between <port> and </port>.
        var inPort = false
        var portId = 0
        var protocol = ""
        var portState = ""
        var service: String? = null
        var product: String? = null
        var version: String? = null
        var extraInfo: String? = null

        try {
            var event = parser.eventType
            while (event != XmlPullParser.END_DOCUMENT) {
                when (event) {
                    XmlPullParser.START_TAG -> when (parser.name) {
                        "host" -> {
                            ipv4 = null; mac = null; vendor = null; status = null
                            hostnames = mutableListOf()
                            osMatches = mutableListOf()
                            ports = mutableListOf()
                        }
                        "status" -> status = parser.getAttributeValue(null, "state")
                        "address" -> {
                            when (parser.getAttributeValue(null, "addrtype")) {
                                "ipv4" -> ipv4 = parser.getAttributeValue(null, "addr")
                                "mac" -> {
                                    mac = parser.getAttributeValue(null, "addr")
                                    vendor = parser.getAttributeValue(null, "vendor")
                                }
                            }
                        }
                        "hostname" -> parser.getAttributeValue(null, "name")
                            ?.takeIf { it.isNotBlank() }
                            ?.let { hostnames.add(it) }
                        "osmatch" -> {
                            val name = parser.getAttributeValue(null, "name")
                            val accuracy = parser.getAttributeValue(null, "accuracy")?.toIntOrNull() ?: 0
                            if (!name.isNullOrBlank()) {
                                osMatches.add(NmapOsMatch(name, accuracy))
                            }
                        }
                        "port" -> {
                            inPort = true
                            portId = parser.getAttributeValue(null, "portid")?.toIntOrNull() ?: 0
                            protocol = parser.getAttributeValue(null, "protocol").orEmpty()
                            portState = ""
                            service = null; product = null; version = null; extraInfo = null
                        }
                        "state" -> if (inPort) {
                            portState = parser.getAttributeValue(null, "state").orEmpty()
                        }
                        "service" -> if (inPort) {
                            service = parser.getAttributeValue(null, "name")
                            product = parser.getAttributeValue(null, "product")
                            version = parser.getAttributeValue(null, "version")
                            extraInfo = parser.getAttributeValue(null, "extrainfo")
                        }
                    }
                    XmlPullParser.END_TAG -> when (parser.name) {
                        "port" -> {
                            if (inPort && portId > 0) {
                                ports.add(
                                    NmapPort(
                                        portId = portId,
                                        protocol = protocol,
                                        state = portState,
                                        service = service,
                                        product = product,
                                        version = version,
                                        extraInfo = extraInfo
                                    )
                                )
                            }
                            inPort = false
                        }
                        "host" -> hosts.add(
                            NmapHost(
                                ipv4 = ipv4,
                                mac = mac,
                                vendor = vendor?.takeIf { it.isNotBlank() },
                                status = status,
                                hostnames = hostnames.toList(),
                                osMatches = osMatches.sortedByDescending { it.accuracy },
                                ports = ports.toList()
                            )
                        )
                    }
                }
                event = parser.next()
            }
        } catch (_: Exception) {
            // Truncated/partial XML: return whatever fully-parsed hosts we have.
        }

        return hosts
    }
}
