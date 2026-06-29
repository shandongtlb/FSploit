package org.fsploit.android.domain.usecase

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AnalyzePcapUseCaseTest {

    @Test
    fun `captures within the cap are not oversize`() {
        assertFalse(AnalyzePcapUseCase.isOversize(0))
        assertFalse(AnalyzePcapUseCase.isOversize(5L * 1024 * 1024))
        assertFalse(AnalyzePcapUseCase.isOversize(AnalyzePcapUseCase.MAX_CAPTURE_BYTES))
    }

    @Test
    fun `captures one byte past the cap are oversize`() {
        assertTrue(AnalyzePcapUseCase.isOversize(AnalyzePcapUseCase.MAX_CAPTURE_BYTES + 1))
    }

    @Test
    fun `large captures are oversize`() {
        assertTrue(AnalyzePcapUseCase.isOversize(128L * 1024 * 1024))
    }
}
