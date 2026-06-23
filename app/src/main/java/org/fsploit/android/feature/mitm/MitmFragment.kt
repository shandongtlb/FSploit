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
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel
import org.fsploit.android.ui.NonFilteringStringAdapter
import org.fsploit.android.ui.enableFullDropdown
import org.fsploit.android.ui.setStatusDot

class MitmFragment : Fragment() {

    private var _binding: FragmentMitmBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by activityViewModels {
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
            viewModel.selectHost(selected)
        }
        binding.targetHostInput.doAfterTextChanged {
            viewModel.selectHost(it?.toString().orEmpty())
        }
        binding.startMitmSessionButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.startMitmSession()
        }
        binding.stopMitmSessionButton.setOnClickListener {
            viewModel.stopMitmSession()
        }
        binding.runMitmDiagnosticsButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.runMitmDiagnostics()
        }
        binding.blockConnectionButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.blockSelectedHost()
        }
        binding.unblockConnectionButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
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

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
        val mode = state.selectedMitmMode
        val useHotspotMode = state.selectedConnectionBlockMode == ConnectionBlockMode.HOTSPOT
        binding.rootGateValue.text = state.rootGateSummary
        binding.mitmSummaryValue.text = state.mitmSummary
        binding.iptablesValue.text = yesNo(state.iptablesAvailable)
        binding.tcpdumpValue.text = yesNo(state.tcpdumpAvailable)
        binding.bettercapValue.text = yesNo(state.bettercapAvailable)
        binding.mitmdumpValue.text = yesNo(state.mitmdumpAvailable)
        binding.caStoreValue.text = yesNo(state.certificateStoreAccessible)
        binding.dotMitmRoot.setStatusDot(state.rootGranted)
        binding.dotIptables.setStatusDot(state.iptablesAvailable)
        binding.dotTcpdump.setStatusDot(state.tcpdumpAvailable)
        binding.dotBettercap.setStatusDot(state.bettercapAvailable)
        binding.dotMitmdump.setStatusDot(state.mitmdumpAvailable)
        binding.dotCaStore.setStatusDot(state.certificateStoreAccessible)
        binding.selectedTargetValue.text = if (state.selectedHostAddress.isBlank()) {
            getString(R.string.discovery_no_target_selected)
        } else {
            getString(R.string.discovery_selected_target, state.selectedHostAddress)
        }
        syncInput(
            binding.mitmGatewayInput,
            state.mitmGatewayInput
        )
        binding.mitmGatewayResolvedValue.text = if (useHotspotMode) {
            getString(R.string.mitm_gateway_hotspot_mode)
        } else if (state.resolvedGatewayAddress.isBlank()) {
            getString(R.string.mitm_gateway_unresolved)
        } else {
            getString(R.string.mitm_gateway_detected, state.resolvedGatewayAddress)
        }
        binding.mitmGatewayInputLayout.visibility = if (useHotspotMode) View.GONE else View.VISIBLE
        binding.mitmModeDescriptionValue.text = getString(mode.descriptionRes)
        binding.currentBlockValue.text = if (state.blockedHostAddress.isBlank()) {
            getString(R.string.block_none)
        } else {
            getString(R.string.block_current_target, state.blockedHostAddress)
        }
        binding.connectionBlockModeDescriptionValue.text =
            getString(state.selectedConnectionBlockMode.descriptionRes)
        binding.connectionBlockModeSummaryValue.text = state.connectionBlockModeSummary
        binding.connectionBlockSummaryValue.text = state.connectionBlockSummary
        binding.activeMitmModeValue.text = if (state.mitmSession.mode == null) {
            getString(R.string.mitm_session_mode_value, getString(R.string.mitm_none))
        } else {
            getString(R.string.mitm_session_mode_value, getString(state.mitmSession.mode.titleRes))
        }
        binding.activeMitmSummaryValue.text = state.mitmSessionSummary
        binding.activeMitmArtifactValue.text = state.mitmSession.artifactPath.ifBlank {
            getString(R.string.mitm_none)
        }
        binding.activeMitmLogValue.text = state.mitmSession.logPath.ifBlank {
            getString(R.string.mitm_none)
        }
        binding.mitmDiagnosticsSummaryValue.text = state.mitmDiagnosticsSummary
        binding.mitmDiagnosticsOutputValue.text = state.mitmDiagnosticsOutput.ifBlank {
            getString(R.string.mitm_diagnostics_output_empty)
        }
        binding.startMitmSessionButton.isEnabled =
            state.rootGranted && state.selectedHostAddress.isNotBlank() && !state.isStartingMitmSession
        binding.stopMitmSessionButton.isEnabled =
            state.rootGranted && state.mitmSession.active && !state.isStartingMitmSession
        binding.runMitmDiagnosticsButton.isEnabled =
            state.rootGranted && state.preferredInterfaceName.isNotBlank() && !state.isRunningMitmDiagnostics
        binding.blockConnectionButton.isEnabled =
            state.rootGranted && state.selectedHostAddress.isNotBlank() && !state.isBlockingConnection
        binding.unblockConnectionButton.isEnabled =
            state.rootGranted && state.selectedHostAddress.isNotBlank() && !state.isBlockingConnection
        val expectedBlockModeButtonId = when (state.selectedConnectionBlockMode) {
            ConnectionBlockMode.NORMAL -> R.id.blockModeNormalButton
            ConnectionBlockMode.HOTSPOT -> R.id.blockModeHotspotButton
        }
        if (binding.connectionBlockModeGroup.checkedButtonId != expectedBlockModeButtonId) {
            binding.connectionBlockModeGroup.check(expectedBlockModeButtonId)
        }

        val targetAdapter = NonFilteringStringAdapter(requireContext(), state.responsiveHosts)
        binding.targetHostInput.setAdapter(targetAdapter)
        if (binding.targetHostInput.text?.toString() != state.selectedHostAddress) {
            binding.targetHostInput.setText(state.selectedHostAddress, false)
        }

        val selectedModeLabel = getString(mode.titleRes)
        if (binding.mitmModeInput.text?.toString() != selectedModeLabel) {
            binding.mitmModeInput.setText(selectedModeLabel, false)
        }

        syncInput(
            binding.mitmPrimaryInput,
            state.mitmPrimaryInput
        )
        syncInput(
            binding.mitmSecondaryInput,
            state.mitmSecondaryInput
        )
        syncInput(
            binding.mitmPayloadInput,
            state.mitmPayloadInput
        )

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
