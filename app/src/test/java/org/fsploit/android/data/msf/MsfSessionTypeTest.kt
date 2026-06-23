package org.fsploit.android.data.msf

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class MsfSessionTypeTest {

    @Test
    fun `meterpreter sessions route to meterpreter transport`() {
        assertTrue(MsfSessionType.isMeterpreter("meterpreter"))
        assertTrue(MsfSessionType.isMeterpreter("Meterpreter"))
        assertTrue(MsfSessionType.isMeterpreter("  METERPRETER  "))
    }

    @Test
    fun `shell and unknown types use the shell transport`() {
        assertFalse(MsfSessionType.isMeterpreter("shell"))
        assertFalse(MsfSessionType.isMeterpreter(""))
        assertFalse(MsfSessionType.isMeterpreter("powershell"))
    }
}
