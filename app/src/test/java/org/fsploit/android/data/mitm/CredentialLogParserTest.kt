package org.fsploit.android.data.mitm

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CredentialLogParserTest {

    private val parser = CredentialLogParser()

    @Test
    fun `lines without any credential signal are dropped`() {
        val log = """
            starting bettercap
            wifi.recon on
            ready
        """.trimIndent()
        assertTrue(parser.parseCredentialsLog(log).isEmpty())
    }

    @Test
    fun `keyword line is kept and exposed verbatim in raw`() {
        val line = "captured authorization header from 10.0.0.5"
        val result = parser.parseCredentialsLog(line)
        assertEquals(1, result.size)
        assertEquals(line, result.first().raw)
    }

    @Test
    fun `username and password are extracted from a key-value line`() {
        val result = parser.parseCredentialsLog("login user=admin password=hunter2")
        assertEquals(1, result.size)
        assertEquals("admin", result.first().username)
        assertEquals("hunter2", result.first().password)
    }

    @Test
    fun `trailing punctuation is stripped off captured values`() {
        val result = parser.parseCredentialsLog("username=bob, password=secret;")
        assertEquals("bob", result.first().username)
        assertEquals("secret", result.first().password)
    }

    @Test
    fun `ansi escape sequences are stripped before parsing`() {
        // bettercap colorizes output with real ANSI escapes (ESC + [..m). The parser strips
        // those before matching, so the credential fields must come out clean.
        val esc = ""
        val colored = "$esc[32m[12:00:01] user=alice password=pw$esc[0m"
        val result = parser.parseCredentialsLog(colored)
        assertEquals(1, result.size)
        val cred = result.first()
        assertEquals("alice", cred.username)
        assertEquals("pw", cred.password)
        assertEquals("12:00:01", cred.timestamp)
        assertTrue("raw should not retain ANSI escapes", !cred.raw.contains(esc))
    }

    @Test
    fun `timestamp and protocol tag are lifted from a net sniff line`() {
        val result = parser.parseCredentialsLog("[09:30:15] [net.sniff.http] user=carol password=p4ss")
        assertEquals(1, result.size)
        val cred = result.first()
        assertEquals("09:30:15", cred.timestamp)
        assertEquals("http", cred.protocol)
    }

    @Test
    fun `a net sniff tag alone qualifies a line even without keywords`() {
        val result = parser.parseCredentialsLog("[net.sniff.tcp] some opaque payload")
        assertEquals(1, result.size)
        assertEquals("tcp", result.first().protocol)
    }

    @Test
    fun `multiple interesting lines each produce an entry`() {
        val log = """
            noise line
            user=u1 password=p1
            [net.sniff.ftp] credential blob
        """.trimIndent()
        assertEquals(2, parser.parseCredentialsLog(log).size)
    }

    @Test
    fun `blank lines are ignored`() {
        assertTrue(parser.parseCredentialsLog("\n\n   \n").isEmpty())
    }
}
