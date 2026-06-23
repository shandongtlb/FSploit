package org.fsploit.android.feature.msf

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentMsfBinding
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.ui.bindCollapsible
import org.fsploit.android.ui.setStatusDot

class MsfFragment : Fragment() {

    private var _binding: FragmentMsfBinding? = null
    private val binding get() = _binding!!

    private val sessionViewModel: SessionViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }
    private val viewModel: MsfViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentMsfBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.msfHostInput.doAfterTextChanged {
            viewModel.updateMsfRpcHost(it?.toString().orEmpty())
        }
        binding.msfPortInput.doAfterTextChanged {
            viewModel.updateMsfRpcPort(it?.toString().orEmpty())
        }
        binding.msfUsernameInput.doAfterTextChanged {
            viewModel.updateMsfRpcUsername(it?.toString().orEmpty())
        }
        binding.msfPasswordInput.doAfterTextChanged {
            viewModel.updateMsfRpcPassword(it?.toString().orEmpty())
        }
        binding.msfUseSslSwitch.setOnCheckedChangeListener { _, isChecked ->
            viewModel.updateMsfRpcUseSsl(isChecked)
        }
        binding.msfLaunchCommandInput.doAfterTextChanged {
            viewModel.updateMsfRpcLaunchCommand(it?.toString().orEmpty())
        }
        binding.applyMsgrpcPresetButton.setOnClickListener {
            viewModel.applyMsfMsgrpcPreset()
        }
        binding.applyMsfrpcdPresetButton.setOnClickListener {
            viewModel.applyMsfMsfrpcdPreset()
        }
        binding.saveMsfSettingsButton.setOnClickListener {
            viewModel.saveMsfRpcConfig()
        }
        binding.refreshMsfButton.setOnClickListener {
            viewModel.refreshMsfOverview()
        }
        binding.launchMsfRpcButton.setOnClickListener {
            viewModel.launchMsfRpcCommand()
        }
        binding.stopSessionButton.setOnClickListener {
            viewModel.stopSession(binding.stopSessionIdInput.text?.toString().orEmpty())
        }
        binding.stopJobButton.setOnClickListener {
            viewModel.stopJob(binding.stopJobIdInput.text?.toString().orEmpty())
        }
        binding.consoleSessionIdInput.doAfterTextChanged {
            viewModel.updateConsoleSessionId(it?.toString().orEmpty())
        }
        binding.consoleSendButton.setOnClickListener { sendConsoleCommand() }
        binding.consoleCommandInput.setOnEditorActionListener { _, _, _ ->
            sendConsoleCommand()
            true
        }
        binding.consoleReadButton.setOnClickListener {
            viewModel.readConsole()
        }
        binding.consoleClearButton.setOnClickListener {
            viewModel.clearConsole()
        }

        bindCollapsible(binding.msfVersionsHeader, binding.msfVersionsBody, binding.msfVersionsChevron)
        bindCollapsible(binding.msfLaunchHeader, binding.msfLaunchOutputValue, binding.msfLaunchChevron)

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                launch { viewModel.uiState.collect(::render) }
                launch { sessionViewModel.uiState.collect(::renderSession) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.refresh()
    }

    private fun sendConsoleCommand() {
        val command = binding.consoleCommandInput.text?.toString().orEmpty()
        if (command.isBlank()) {
            return
        }
        viewModel.sendConsoleCommand(command)
        binding.consoleCommandInput.setText("")
    }

    private fun renderSession(state: SessionState) {
        binding.rootGateValue.text = state.rootGateSummary
        binding.shellSummaryValue.text = state.shellSummary
        binding.dotMsfRoot.setStatusDot(state.rootGranted)
        binding.dotMsfShell.setStatusDot(state.shellAvailable)
        binding.launchMsfRpcButton.isEnabled = state.rootGranted && !viewModel.uiState.value.isLaunchingMsfRpc
    }

    private fun render(state: MsfUiState) {
        binding.msfSummaryValue.text = state.msfSummary
        binding.dotMsfConnected.setStatusDot(state.msfConnected)
        binding.msfConnectedValue.text = getString(
            if (state.msfConnected) R.string.msf_connected else R.string.msf_disconnected
        )
        binding.msfVersionValue.text = state.msfFrameworkVersion.ifBlank {
            getString(R.string.msf_value_unknown)
        }
        binding.msfRubyValue.text = state.msfRubyVersion.ifBlank {
            getString(R.string.msf_value_unknown)
        }
        binding.msfApiValue.text = state.msfApiVersion.ifBlank {
            getString(R.string.msf_value_unknown)
        }
        binding.savedMsfConfigValue.text = getString(
            R.string.msf_config_value,
            state.msfRpcConfig.host,
            state.msfRpcConfig.port,
            state.msfRpcConfig.username,
            getString(
                if (state.msfRpcConfig.useSsl) {
                    R.string.msf_ssl_enabled
                } else {
                    R.string.msf_ssl_disabled
                }
            )
        )
        syncInput(binding.msfHostInput, state.msfRpcConfig.host)
        syncInput(binding.msfPortInput, state.msfRpcConfig.port.toString())
        syncInput(binding.msfUsernameInput, state.msfRpcConfig.username)
        syncInput(binding.msfPasswordInput, state.msfRpcConfig.password)
        syncInput(binding.msfLaunchCommandInput, state.msfRpcConfig.launchCommand)
        if (binding.msfUseSslSwitch.isChecked != state.msfRpcConfig.useSsl) {
            binding.msfUseSslSwitch.isChecked = state.msfRpcConfig.useSsl
        }
        binding.msfSettingsSummaryValue.text = state.msfSettingsSummary
        binding.msfLaunchSummaryValue.text = state.msfLaunchSummary
        binding.msfLaunchOutputValue.text = state.msfLaunchOutput.ifBlank {
            getString(R.string.msf_launch_output_empty)
        }
        binding.msfSessionsValue.text = if (state.msfSessions.isEmpty()) {
            getString(R.string.msf_sessions_empty)
        } else {
            state.msfSessions.joinToString(separator = "\n\n") { session ->
                buildString {
                    append("#")
                    append(session.id)
                    append("  ")
                    append(session.type.ifBlank { getString(R.string.msf_value_unknown) })
                    append('\n')
                    append(getString(R.string.msf_session_target, session.targetHost.ifBlank { "-" }))
                    append('\n')
                    append(getString(R.string.msf_session_peer, session.tunnelPeer.ifBlank { "-" }))
                    append('\n')
                    append(getString(R.string.msf_session_via, session.viaExploit.ifBlank { "-" }))
                    if (session.description.isNotBlank()) {
                        append('\n')
                        append(session.description)
                    }
                }
            }
        }
        binding.msfJobsValue.text = if (state.msfJobs.isEmpty()) {
            getString(R.string.msf_jobs_empty)
        } else {
            state.msfJobs.joinToString(separator = "\n") { job ->
                "#${job.id}  ${job.name.ifBlank { getString(R.string.msf_value_unknown) }}"
            }
        }
        binding.msfActionSummaryValue.text = state.msfActionSummary
        syncInput(binding.consoleSessionIdInput, state.consoleSessionId)
        binding.consoleOutputValue.text = state.consoleOutput.ifBlank {
            getString(R.string.msf_console_output_empty)
        }
        binding.consoleSummaryValue.text = state.consoleSummary

        binding.saveMsfSettingsButton.isEnabled = !state.isSavingMsfRpcConfig
        binding.refreshMsfButton.isEnabled = !state.isRefreshingMsf
        binding.launchMsfRpcButton.isEnabled = sessionViewModel.uiState.value.rootGranted && !state.isLaunchingMsfRpc
        binding.stopSessionButton.isEnabled = !state.isRunningMsfAction
        binding.stopJobButton.isEnabled = !state.isRunningMsfAction
        binding.consoleSendButton.isEnabled = !state.isConsoleBusy
        binding.consoleReadButton.isEnabled = !state.isConsoleBusy
    }

    private fun syncInput(input: com.google.android.material.textfield.TextInputEditText, value: String) {
        if (input.text?.toString() != value) {
            input.setText(value)
            input.setSelection(input.text?.length ?: 0)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
