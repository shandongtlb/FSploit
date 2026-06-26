package org.fsploit.android.feature.tools

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.fsploit.android.R
import org.fsploit.android.core.ResourceProvider
import org.fsploit.android.core.ShellTaskPreset
import org.fsploit.android.domain.usecase.RunShellCommandUseCase
import org.fsploit.android.feature.session.SessionStateHolder

data class ToolsUiState(
    val selectedShellTaskLabel: String = "",
    val selectedShellTaskDescription: String = "",
    val shellCommandInput: String = "",
    val shellRunAsRoot: Boolean = false,
    val shellExecutionSummary: String = "",
    val shellExecutionOutput: String = "",
    val isExecutingShell: Boolean = false
)

class ToolsViewModel(
    private val resourceProvider: ResourceProvider,
    private val session: SessionStateHolder,
    private val runShellCommandUseCase: RunShellCommandUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(
        ToolsUiState(
            selectedShellTaskLabel = resourceProvider.getString(R.string.shell_task_custom),
            selectedShellTaskDescription = resourceProvider.getString(R.string.shell_task_custom_desc),
            shellExecutionSummary = resourceProvider.getString(R.string.shell_command_idle)
        )
    )
    val uiState: StateFlow<ToolsUiState> = _uiState.asStateFlow()

    fun updateShellCommand(command: String) {
        _uiState.value = _uiState.value.copy(
            shellCommandInput = command,
            selectedShellTaskLabel = resourceProvider.getString(R.string.shell_task_custom),
            selectedShellTaskDescription = resourceProvider.getString(R.string.shell_task_custom_desc)
        )
    }

    fun updateShellRunAsRoot(asRoot: Boolean) {
        _uiState.value = _uiState.value.copy(shellRunAsRoot = asRoot)
    }

    fun applyShellPreset(command: String) {
        _uiState.value = _uiState.value.copy(shellCommandInput = command)
    }

    fun applyShellTaskPreset(task: ShellTaskPreset) {
        _uiState.value = _uiState.value.copy(
            selectedShellTaskLabel = resourceProvider.getString(task.titleRes),
            selectedShellTaskDescription = resourceProvider.getString(task.descriptionRes),
            shellCommandInput = task.command,
            shellRunAsRoot = task.runAsRoot
        )
    }

    fun runShellCommand() {
        val state = _uiState.value
        if (!session.value.rootGranted && state.shellRunAsRoot) {
            _uiState.value = state.copy(
                shellExecutionSummary = resourceProvider.getString(R.string.root_gate_blocked),
                shellExecutionOutput = ""
            )
            return
        }
        val command = state.shellCommandInput.trim()
        if (command.isEmpty()) {
            _uiState.value = state.copy(
                shellExecutionSummary = resourceProvider.getString(R.string.shell_command_empty),
                shellExecutionOutput = ""
            )
            return
        }

        viewModelScope.launch {
            _uiState.value = state.copy(
                isExecutingShell = true,
                shellExecutionSummary = resourceProvider.getString(R.string.shell_command_running)
            )

            val result = withContext(Dispatchers.IO) {
                runShellCommandUseCase(
                    command = command,
                    asRoot = state.shellRunAsRoot,
                    timeoutMs = SHELL_COMMAND_TIMEOUT_MS
                )
            }

            _uiState.value = _uiState.value.copy(
                isExecutingShell = false,
                shellExecutionSummary = result.summary,
                shellExecutionOutput = result.output.ifBlank {
                    resourceProvider.getString(R.string.shell_command_no_output)
                }
            )
        }
    }

    companion object {
        private const val SHELL_COMMAND_TIMEOUT_MS = 5000L
    }
}
