package org.fsploit.android.feature.discovery

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.MainScreen
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentDiscoveryBinding
import org.fsploit.android.databinding.ItemResponsiveTargetBinding
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

class DiscoveryFragment : Fragment() {

    private var _binding: FragmentDiscoveryBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentDiscoveryBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.saveInterfaceButton.setOnClickListener {
            viewModel.savePreferredInterface(binding.preferredInterfaceInput.text?.toString().orEmpty())
        }
        binding.runSweepButton.setOnClickListener {
            viewModel.savePreferredInterface(binding.preferredInterfaceInput.text?.toString().orEmpty())
            viewModel.runSweep()
        }
        binding.openTargetButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            (requireActivity() as MainActivity).openScreen(MainScreen.TARGET_DETAIL)
        }
        binding.targetHostInput.setOnItemClickListener { _, _, position, _ ->
            val selected = binding.targetHostInput.adapter.getItem(position)?.toString().orEmpty()
            viewModel.selectHost(selected)
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
        binding.discoveryHint.text = getString(R.string.discovery_hint)
        binding.saveInterfaceButton.isEnabled = state.interfaces.isNotEmpty()
        binding.runSweepButton.isEnabled = state.canContinue && !state.isScanning
        binding.openTargetButton.isEnabled = state.selectedHostAddress.isNotBlank()
        binding.selectedTargetValue.text = if (state.selectedHostAddress.isBlank()) {
            getString(R.string.discovery_no_target_selected)
        } else {
            getString(R.string.discovery_selected_target, state.selectedHostAddress)
        }

        binding.preferredInterfaceInput.setAdapter(
            ArrayAdapter(
                requireContext(),
                android.R.layout.simple_dropdown_item_1line,
                state.interfaces.map { it.name }
            )
        )
        if (binding.preferredInterfaceInput.text?.toString() != state.preferredInterfaceName) {
            binding.preferredInterfaceInput.setText(state.preferredInterfaceName, false)
        }

        binding.scanSummaryValue.text = state.scanSummary
        binding.scanResultsValue.text = if (state.scanResults.isEmpty()) {
            getString(R.string.no_scan_results)
        } else {
            state.scanResults.joinToString(separator = "\n")
        }
        binding.targetsEmptyValue.text = if (state.responsiveTargetResults.isEmpty()) {
            getString(R.string.discovery_no_targets)
        } else {
            ""
        }
        renderResponsiveTargets(state)

        binding.targetHostInput.setAdapter(
            ArrayAdapter(
                requireContext(),
                android.R.layout.simple_dropdown_item_1line,
                state.responsiveHosts
            )
        )
        if (binding.targetHostInput.text?.toString() != state.selectedHostAddress) {
            binding.targetHostInput.setText(state.selectedHostAddress, false)
        }
    }

    private fun renderResponsiveTargets(state: HomeUiState) {
        binding.responsiveTargetsContainer.removeAllViews()
        state.responsiveTargetResults.forEach { target ->
            val itemBinding = ItemResponsiveTargetBinding.inflate(layoutInflater, binding.responsiveTargetsContainer, false)
            itemBinding.hostAddressValue.text = target.hostAddress
            itemBinding.hostFindingValue.text = target.finding
            val isSelected = target.hostAddress == state.selectedHostAddress
            itemBinding.root.strokeWidth = if (isSelected) {
                resources.getDimensionPixelSize(R.dimen.discovery_target_selected_stroke)
            } else {
                resources.getDimensionPixelSize(R.dimen.discovery_target_default_stroke)
            }
            itemBinding.root.strokeColor = requireContext().getColor(
                if (isSelected) {
                    R.color.fsploit_primary
                } else {
                    R.color.fsploit_stroke
                }
            )
            itemBinding.root.setOnClickListener {
                viewModel.selectHost(target.hostAddress)
                (requireActivity() as MainActivity).openScreen(MainScreen.TARGET_DETAIL)
            }
            binding.responsiveTargetsContainer.addView(itemBinding.root)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
