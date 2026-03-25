package org.fsploit.android.data.mitm

import org.fsploit.android.domain.model.MitmActionResult
import org.fsploit.android.domain.model.MitmLaunchRequest
import org.fsploit.android.domain.model.MitmReadiness
import org.fsploit.android.domain.model.MitmSession
import org.fsploit.android.domain.model.ShellStatus

interface MitmBackend {
    fun loadReadiness(shellStatus: ShellStatus): MitmReadiness
    fun loadSession(): MitmSession
    fun startSession(request: MitmLaunchRequest): MitmActionResult
    fun stopSession(): MitmActionResult
}
