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
import org.fsploit.android.data.msf.MsfPayloads
import org.fsploit.android.data.msf.MsfScanners
import org.fsploit.android.databinding.FragmentMsfBinding
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.ui.NonFilteringStringAdapter
import org.fsploit.android.ui.bindCollapsible
import org.fsploit.android.ui.enableFullDropdown
import org.fsploit.android.ui.setStatusDot
import org.fsploit.android.ui.showInfoBubble

class MsfFragment : Fragment() {

    private var _binding: FragmentMsfBinding? = null
    private val binding get() = _binding!!

    private val scannerLabels: List<String> = MsfScanners.COMMON.map { it.label }

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
        binding.applyMsgrpcPresetButton.setOnClickListener {
            viewModel.applyMsfMsgrpcPreset()
        }
        binding.saveMsfSettingsButton.setOnClickListener {
            viewModel.saveMsfRpcConfig()
        }
        binding.refreshMsfButton.setOnClickListener {
            viewModel.refreshMsfOverview()
        }
        binding.pushTargetButton.setOnClickListener {
            viewModel.pushSelectedHostToMsf()
        }
        binding.msfHelpInfo.setOnClickListener {
            showInfoBubble(
                anchor = it,
                body = getString(R.string.msf_help_body),
                copyText = getString(R.string.msf_help_command)
            )
        }
        binding.stopSessionButton.setOnClickListener {
            viewModel.stopSession(binding.stopSessionIdInput.text?.toString().orEmpty())
        }
        binding.stopJobButton.setOnClickListener {
            viewModel.stopJob(binding.stopJobIdInput.text?.toString().orEmpty())
        }

        // Stop a session/job by picking its id from the live list — no hand-typed ids.
        binding.stopSessionIdInput.enableFullDropdown()
        binding.stopJobIdInput.enableFullDropdown()

        // Vuln scan — curated auxiliary scanner dropdown pushed into the shared instance.
        binding.scanModuleInput.enableFullDropdown()
        binding.scanModuleInput.setAdapter(NonFilteringStringAdapter(requireContext(), scannerLabels))
        binding.scanModuleInput.setOnItemClickListener { _, _, position, _ ->
            viewModel.updateScanModule(MsfScanners.COMMON[position].modulePath)
        }
        binding.scanRhostsInput.doAfterTextChanged { viewModel.updateScanRhosts(it?.toString().orEmpty()) }
        binding.runScanButton.setOnClickListener { viewModel.runVulnScan() }

        // Listener + payload (A) — payload picked from a curated dropdown, not typed.
        binding.payloadInput.enableFullDropdown()
        binding.payloadInput.setAdapter(NonFilteringStringAdapter(requireContext(), MsfPayloads.COMMON))
        binding.payloadInput.setOnItemClickListener { _, _, position, _ ->
            viewModel.updatePayload(MsfPayloads.COMMON[position])
        }
        binding.lhostInput.doAfterTextChanged { viewModel.updateLhost(it?.toString().orEmpty()) }
        binding.lportInput.doAfterTextChanged { viewModel.updateLport(it?.toString().orEmpty()) }
        binding.startHandlerButton.setOnClickListener { viewModel.startHandler() }

        bindCollapsible(binding.msfVersionsHeader, binding.msfVersionsBody, binding.msfVersionsChevron)
        bindCollapsible(binding.advancedMsfHeader, binding.advancedMsfBody, binding.advancedMsfChevron)

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

    private fun renderSession(state: SessionState) {
        binding.rootGateValue.text = state.rootGateSummary
        binding.shellSummaryValue.text = state.shellSummary
        binding.dotMsfRoot.setStatusDot(state.rootGranted)
        binding.dotMsfShell.setStatusDot(state.shellAvailable)
        val msf = viewModel.uiState.value
        binding.pushTargetButton.isEnabled =
            msf.msfConnected && state.selectedHostAddress.isNotBlank() && !msf.isPushingTarget
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
        if (binding.msfUseSslSwitch.isChecked != state.msfRpcConfig.useSsl) {
            binding.msfUseSslSwitch.isChecked = state.msfRpcConfig.useSsl
        }
        binding.msfSettingsSummaryValue.text = state.msfSettingsSummary
        binding.pushTargetSummaryValue.text = state.pushTargetSummary
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
        // Stop dropdowns list the live session/job ids — selection over hand-typed numbers.
        binding.stopSessionIdInput.setSimpleItems(state.msfSessions.map { it.id }.toTypedArray())
        binding.stopJobIdInput.setSimpleItems(state.msfJobs.map { it.id }.toTypedArray())

        // Vuln scan
        val scanLabel = MsfScanners.COMMON.firstOrNull { it.modulePath == state.scanModulePath }?.label
            ?: state.scanModulePath
        if (binding.scanModuleInput.text?.toString() != scanLabel) {
            binding.scanModuleInput.setText(scanLabel, false)
        }
        syncInput(binding.scanRhostsInput, state.scanRhosts)
        binding.scanSummaryValue.text = state.scanSummary
        binding.scanOutputValue.text = state.scanOutput.ifBlank {
            getString(R.string.msf_scan_output_empty)
        }

        // Listener + payload (A)
        if (binding.payloadInput.text?.toString() != state.payload) {
            binding.payloadInput.setText(state.payload, false)
        }
        syncInput(binding.lhostInput, state.lhost)
        syncInput(binding.lportInput, state.lport)
        binding.handlerSummaryValue.text = state.handlerSummary

        binding.saveMsfSettingsButton.isEnabled = !state.isSavingMsfRpcConfig
        binding.refreshMsfButton.isEnabled = !state.isRefreshingMsf
        binding.pushTargetButton.isEnabled =
            state.msfConnected && sessionViewModel.uiState.value.selectedHostAddress.isNotBlank() && !state.isPushingTarget
        binding.stopSessionButton.isEnabled = !state.isRunningMsfAction
        binding.stopJobButton.isEnabled = !state.isRunningMsfAction
        binding.runScanButton.isEnabled = state.msfConnected && !state.isScanning
        binding.startHandlerButton.isEnabled = state.msfConnected && !state.isStartingHandler
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
