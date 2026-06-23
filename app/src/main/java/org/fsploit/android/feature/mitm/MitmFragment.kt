package org.fsploit.android.feature.mitm

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
import org.fsploit.android.databinding.FragmentMitmBinding
import org.fsploit.android.domain.model.ConnectionBlockMode
import org.fsploit.android.domain.model.MitmMode
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.ui.NonFilteringStringAdapter
import org.fsploit.android.ui.bindCollapsible
import org.fsploit.android.ui.enableFullDropdown
import org.fsploit.android.ui.setStatusDot

class MitmFragment : Fragment() {

    private var _binding: FragmentMitmBinding? = null
    private val binding get() = _binding!!

    private val sessionViewModel: SessionViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }
    private val viewModel: MitmViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentMitmBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.targetHostInput.enableFullDropdown()
        binding.mitmModeInput.enableFullDropdown()
        binding.targetHostInput.setOnItemClickListener { _, _, position, _ ->
            val selected = binding.targetHostInput.adapter.getItem(position)?.toString().orEmpty()
            sessionViewModel.selectHost(selected)
        }
        binding.targetHostInput.doAfterTextChanged {
            sessionViewModel.selectHost(it?.toString().orEmpty())
        }
        binding.startMitmSessionButton.setOnClickListener {
            sessionViewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.startMitmSession()
        }
        binding.stopMitmSessionButton.setOnClickListener {
            viewModel.stopMitmSession()
        }
        binding.runMitmDiagnosticsButton.setOnClickListener {
            sessionViewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.runMitmDiagnostics()
        }
        binding.blockConnectionButton.setOnClickListener {
            sessionViewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.blockSelectedHost()
        }
        binding.unblockConnectionButton.setOnClickListener {
            sessionViewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.unblockSelectedHost()
        }
        binding.connectionBlockModeGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) {
                return@addOnButtonCheckedListener
            }
            val mode = when (checkedId) {
                R.id.blockModeHotspotButton -> ConnectionBlockMode.HOTSPOT
                else -> ConnectionBlockMode.NORMAL
            }
            viewModel.selectConnectionBlockMode(mode)
        }
        binding.mitmPrimaryInput.doAfterTextChanged {
            viewModel.updateMitmPrimaryInput(it?.toString().orEmpty())
        }
        binding.mitmGatewayInput.doAfterTextChanged {
            viewModel.updateMitmGatewayInput(it?.toString().orEmpty())
        }
        binding.mitmSecondaryInput.doAfterTextChanged {
            viewModel.updateMitmSecondaryInput(it?.toString().orEmpty())
        }
        binding.mitmPayloadInput.doAfterTextChanged {
            viewModel.updateMitmPayloadInput(it?.toString().orEmpty())
        }

        val modeLabels = MitmMode.entries.map { getString(it.titleRes) }
        binding.mitmModeInput.setAdapter(NonFilteringStringAdapter(requireContext(), modeLabels))
        binding.mitmModeInput.setOnItemClickListener { _, _, position, _ ->
            viewModel.selectMitmMode(MitmMode.entries[position])
        }

        // Low-frequency sections collapse to keep the core controls in focus.
        bindCollapsible(binding.readinessHeader, binding.readinessBody, binding.readinessChevron)
        bindCollapsible(binding.advancedHeader, binding.advancedBody, binding.advancedChevron)

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                launch { viewModel.uiState.collect { renderAll() } }
                launch { sessionViewModel.uiState.collect { renderAll() } }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.refresh()
    }

    private fun renderAll() {
        val s: SessionState = sessionViewModel.uiState.value
        val m: MitmUiState = viewModel.uiState.value
        val mode = m.selectedMitmMode
        val useHotspotMode = m.selectedConnectionBlockMode == ConnectionBlockMode.HOTSPOT

        binding.rootGateValue.text = s.rootGateSummary
        binding.mitmSummaryValue.text = m.mitmSummary
        binding.iptablesValue.text = yesNo(m.iptablesAvailable)
        binding.tcpdumpValue.text = yesNo(m.tcpdumpAvailable)
        binding.bettercapValue.text = yesNo(m.bettercapAvailable)
        binding.mitmdumpValue.text = yesNo(m.mitmdumpAvailable)
        binding.caStoreValue.text = yesNo(m.certificateStoreAccessible)
        binding.dotMitmRoot.setStatusDot(s.rootGranted)
        binding.dotIptables.setStatusDot(m.iptablesAvailable)
        binding.dotTcpdump.setStatusDot(m.tcpdumpAvailable)
        binding.dotBettercap.setStatusDot(m.bettercapAvailable)
        binding.dotMitmdump.setStatusDot(m.mitmdumpAvailable)
        binding.dotCaStore.setStatusDot(m.certificateStoreAccessible)
        val envReady = s.rootGranted && m.iptablesAvailable && m.tcpdumpAvailable &&
            m.bettercapAvailable && m.mitmdumpAvailable && m.certificateStoreAccessible
        binding.dotReadiness.setStatusDot(envReady)
        binding.readinessStatusValue.text =
            getString(if (envReady) R.string.mitm_env_ready else R.string.mitm_env_not_ready)
        binding.selectedTargetValue.text = if (s.selectedHostAddress.isBlank()) {
            getString(R.string.discovery_no_target_selected)
        } else {
            getString(R.string.discovery_selected_target, s.selectedHostAddress)
        }
        syncInput(binding.mitmGatewayInput, m.mitmGatewayInput)
        binding.mitmGatewayResolvedValue.text = if (useHotspotMode) {
            getString(R.string.mitm_gateway_hotspot_mode)
        } else if (s.resolvedGatewayAddress.isBlank()) {
            getString(R.string.mitm_gateway_unresolved)
        } else {
            getString(R.string.mitm_gateway_detected, s.resolvedGatewayAddress)
        }
        binding.mitmGatewayInputLayout.visibility = if (useHotspotMode) View.GONE else View.VISIBLE
        binding.mitmModeDescriptionValue.text = getString(mode.descriptionRes)
        binding.currentBlockValue.text = if (m.blockedHostAddress.isBlank()) {
            getString(R.string.block_none)
        } else {
            getString(R.string.block_current_target, m.blockedHostAddress)
        }
        binding.connectionBlockModeDescriptionValue.text = getString(m.selectedConnectionBlockMode.descriptionRes)
        binding.connectionBlockModeSummaryValue.text = m.connectionBlockModeSummary
        binding.connectionBlockSummaryValue.text = m.connectionBlockSummary
        binding.activeMitmModeValue.text = if (m.mitmSession.mode == null) {
            getString(R.string.mitm_session_mode_value, getString(R.string.mitm_none))
        } else {
            getString(R.string.mitm_session_mode_value, getString(m.mitmSession.mode.titleRes))
        }
        binding.activeMitmSummaryValue.text = m.mitmSessionSummary
        binding.activeMitmArtifactValue.text = m.mitmSession.artifactPath.ifBlank {
            getString(R.string.mitm_none)
        }
        binding.activeMitmLogValue.text = m.mitmSession.logPath.ifBlank {
            getString(R.string.mitm_none)
        }
        binding.mitmDiagnosticsSummaryValue.text = m.mitmDiagnosticsSummary
        binding.mitmDiagnosticsOutputValue.text = m.mitmDiagnosticsOutput.ifBlank {
            getString(R.string.mitm_diagnostics_output_empty)
        }
        binding.startMitmSessionButton.isEnabled =
            s.rootGranted && s.selectedHostAddress.isNotBlank() && !m.isStartingMitmSession
        binding.stopMitmSessionButton.isEnabled =
            s.rootGranted && m.mitmSession.active && !m.isStartingMitmSession
        binding.runMitmDiagnosticsButton.isEnabled =
            s.rootGranted && s.preferredInterfaceName.isNotBlank() && !m.isRunningMitmDiagnostics
        binding.blockConnectionButton.isEnabled =
            s.rootGranted && s.selectedHostAddress.isNotBlank() && !m.isBlockingConnection
        binding.unblockConnectionButton.isEnabled =
            s.rootGranted && s.selectedHostAddress.isNotBlank() && !m.isBlockingConnection
        val expectedBlockModeButtonId = when (m.selectedConnectionBlockMode) {
            ConnectionBlockMode.NORMAL -> R.id.blockModeNormalButton
            ConnectionBlockMode.HOTSPOT -> R.id.blockModeHotspotButton
        }
        if (binding.connectionBlockModeGroup.checkedButtonId != expectedBlockModeButtonId) {
            binding.connectionBlockModeGroup.check(expectedBlockModeButtonId)
        }

        binding.targetHostInput.setAdapter(NonFilteringStringAdapter(requireContext(), s.responsiveHosts))
        if (binding.targetHostInput.text?.toString() != s.selectedHostAddress) {
            binding.targetHostInput.setText(s.selectedHostAddress, false)
        }

        val selectedModeLabel = getString(mode.titleRes)
        if (binding.mitmModeInput.text?.toString() != selectedModeLabel) {
            binding.mitmModeInput.setText(selectedModeLabel, false)
        }

        syncInput(binding.mitmPrimaryInput, m.mitmPrimaryInput)
        syncInput(binding.mitmSecondaryInput, m.mitmSecondaryInput)
        syncInput(binding.mitmPayloadInput, m.mitmPayloadInput)

        renderModeFields(mode)
    }

    private fun renderModeFields(mode: MitmMode) {
        // Each per-mode input simply appears with its own labelled hint, or is hidden
        // entirely when the mode does not use it — no "field not needed" filler text.
        binding.mitmPrimaryInputLayout.visibility = if (mode.showsPrimaryInput) View.VISIBLE else View.GONE
        binding.mitmPrimaryInputLayout.hint = getString(mode.primaryHintRes ?: R.string.mitm_primary_input_label)
        binding.mitmSecondaryInputLayout.visibility = if (mode.showsSecondaryInput) View.VISIBLE else View.GONE
        binding.mitmSecondaryInputLayout.hint = getString(mode.secondaryHintRes ?: R.string.mitm_secondary_input_label)
        binding.mitmPayloadInputLayout.visibility = if (mode.showsPayloadInput) View.VISIBLE else View.GONE
        binding.mitmPayloadInputLayout.hint = getString(mode.payloadHintRes ?: R.string.mitm_payload_input_label)
    }

    private fun syncInput(input: com.google.android.material.textfield.TextInputEditText, value: String) {
        if (input.text?.toString() != value) {
            input.setText(value)
            input.setSelection(input.text?.length ?: 0)
        }
    }

    private fun yesNo(value: Boolean): String {
        return if (value) getString(R.string.mitm_available) else getString(R.string.mitm_unavailable)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
