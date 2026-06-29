package org.fsploit.android.domain.usecase

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AnalyzePcapUseCaseTest {

    @Test
    fun `captures within the cap are accepted`() {
        assertNull(AnalyzePcapUseCase.oversizeCaptureNote(0))
        assertNull(AnalyzePcapUseCase.oversizeCaptureNote(5L * 1024 * 1024))
        assertNull(AnalyzePcapUseCase.oversizeCaptureNote(AnalyzePcapUseCase.MAX_CAPTURE_BYTES))
    }

    @Test
    fun `captures past the cap are rejected with an explanatory note`() {
        val note = AnalyzePcapUseCase.oversizeCaptureNote(AnalyzePcapUseCase.MAX_CAPTURE_BYTES + 1)
        assertNotNull(note)
        assertTrue("note should mention the size", note!!.contains("MB"))
        assertTrue("note should point at an alternative", note.contains("tshark"))
    }

    @Test
    fun `note reports the actual capture size in MB`() {
        val note = AnalyzePcapUseCase.oversizeCaptureNote(128L * 1024 * 1024)
        assertNotNull(note)
        assertTrue("note should report 128 MB", note!!.contains("128 MB"))
    }
}
