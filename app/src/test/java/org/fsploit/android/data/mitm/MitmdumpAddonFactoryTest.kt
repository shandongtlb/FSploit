package org.fsploit.android.data.mitm

import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MitmdumpAddonFactoryTest {

    private val factory = MitmdumpAddonFactory(FakeResourceProvider())

    @Test
    fun `redirect addon normalizes host and port`() {
        val addon = factory.build(
            request = MitmLaunchRequest(
                mode = MitmMode.REDIRECT,
                targetHost = "192.168.1.20",
                interfaceName = "wlan0",
                primaryValue = "example.com",
                secondaryValue = "8080"
            ),
            artifactPath = "/tmp/unused.py"
        )

        assertTrue(addon.contains("TARGET_HOST = 'example.com'"))
        assertTrue(addon.contains("TARGET_PORT = 8080"))
        assertTrue(addon.contains("flow.request.headers[\"Host\"] = TARGET_HOST"))
    }

    @Test
    fun `script injection rejects blank payload`() {
        val error = runCatching {
            factory.build(
                request = MitmLaunchRequest(
                    mode = MitmMode.SCRIPT_INJECTION,
                    targetHost = "192.168.1.20",
                    interfaceName = "wlan0",
                    payloadValue = "   "
                ),
                artifactPath = "/tmp/inject.py"
            )
        }.exceptionOrNull()

        assertEquals("script required", error?.message)
    }

    @Test
    fun `custom filter rejects malformed rules`() {
        val error = runCatching {
            factory.build(
                request = MitmLaunchRequest(
                    mode = MitmMode.CUSTOM_FILTER,
                    targetHost = "192.168.1.20",
                    interfaceName = "wlan0",
                    payloadValue = "broken rule"
                ),
                artifactPath = "/tmp/filter.py"
            )
        }.exceptionOrNull()

        assertEquals("invalid filter rule: broken rule", error?.message)
    }

    @Test
    fun `session hijack addon writes to artifact path`() {
        val addon = factory.build(
            request = MitmLaunchRequest(
                mode = MitmMode.SESSION_HIJACK,
                targetHost = "192.168.1.20",
                interfaceName = "wlan0"
            ),
            artifactPath = "/tmp/cookies.jsonl"
        )

        assertTrue(addon.contains("COOKIE_LOG = '/tmp/cookies.jsonl'"))
        assertTrue(addon.contains("json.dumps(record, ensure_ascii=False)"))
    }

    @Test
    fun `mitm mode field metadata stays centralized`() {
        assertTrue(MitmMode.REDIRECT.showsPrimaryInput)
        assertTrue(MitmMode.REDIRECT.showsSecondaryInput)
        assertFalse(MitmMode.REDIRECT.showsPayloadInput)
        assertTrue(MitmMode.CUSTOM_FILTER.showsPayloadInput)
        assertFalse(MitmMode.SNIFFER.showsPrimaryInput)
        assertTrue(MitmMode.SESSION_HIJACK.usesHttpMitmAddon)
        assertFalse(MitmMode.SNIFFER.usesHttpMitmAddon)
    }

    private class FakeResourceProvider : ResourceProvider {
        override fun getString(resId: Int, vararg formatArgs: Any): String {
            val template = when (resId) {
                R.string.mitm_mode_not_supported -> "mode not supported"
                R.string.mitm_redirect_port_invalid -> "redirect port invalid"
                R.string.mitm_video_url_invalid -> "video invalid"
                R.string.mitm_script_required -> "script required"
                R.string.mitm_filter_rules_required -> "filter rules required"
                R.string.mitm_filter_rule_invalid -> "invalid filter rule: %s"
                R.string.mitm_url_invalid -> "url invalid"
                R.string.mitm_redirect_host_invalid -> "redirect host invalid"
                else -> "res-$resId"
            }
            return if (formatArgs.isEmpty()) {
                template
            } else {
                template.format(*formatArgs)
            }
        }
    }
}
