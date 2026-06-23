package org.fsploit.android.feature.session

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Process-wide single source of truth for [SessionState]. A plain (non-ViewModel) holder so that
 * both [SessionViewModel] and every per-feature ViewModel can share it without a ViewModel ever
 * depending on another ViewModel. Lives for the lifetime of the app in the DI container.
 */
class SessionStateHolder {
    private val _state = MutableStateFlow(SessionState())
    val state: StateFlow<SessionState> = _state.asStateFlow()

    val value: SessionState get() = _state.value

    fun update(transform: (SessionState) -> SessionState) {
        _state.value = transform(_state.value)
    }
}
