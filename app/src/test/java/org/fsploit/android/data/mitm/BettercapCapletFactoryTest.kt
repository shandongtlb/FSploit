package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BettercapCapletFactoryTest {

    private val factory = BettercapCapletFactory(FakeResourceProvider())

    @Test
    fun `arp spoof caplet contains gateway and target`() {
        val caplet = factory.buildArpSpoofCaplet("192.168.1.20", "192.168.1.1")

        assertTrue(caplet.contains("set gateway.address 192.168.1.1"))
        assertTrue(caplet.contains("set arp.spoof.targets 192.168.1.20"))
        assertTrue(caplet.contains("arp.spoof on"))
    }

    @Test
    fun `dns rules normalize host records for bettercap`() {
        val normalized = factory.normalizeDnsRules(
            """
            example.com A 10.0.0.5
            demo.local 10.0.0.9
            """.trimIndent()
        )

        assertEquals("10.0.0.5 example.com\n10.0.0.9 demo.local\n", normalized)
    }

    @Test
    fun `dns rule validation rejects malformed lines`() {
        val error = runCatching {
            factory.normalizeDnsRules("broken")
        }.exceptionOrNull()

        assertEquals("invalid filter rule: broken", error?.message)
    }

    private class FakeResourceProvider : ResourceProvider {
        override fun getString(resId: Int, vararg formatArgs: Any): String {
            val template = when (resId) {
                R.string.mitm_filter_rule_invalid -> "invalid filter rule: %s"
                else -> "res-$resId"
            }
            return if (formatArgs.isEmpty()) template else template.format(*formatArgs)
        }
    }
}
