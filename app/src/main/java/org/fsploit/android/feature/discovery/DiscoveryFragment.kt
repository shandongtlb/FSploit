package org.fsploit.android.feature.discovery

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
import org.fsploit.android.MainScreen
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentDiscoveryBinding
import org.fsploit.android.databinding.ItemResponsiveTargetBinding
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.ui.NonFilteringStringAdapter
import org.fsploit.android.ui.enableFullDropdown

class DiscoveryFragment : Fragment() {

    private var _binding: FragmentDiscoveryBinding? = null
    private val binding get() = _binding!!

    private val viewModel: SessionViewModel by activityViewModels {
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

        binding.preferredInterfaceInput.enableFullDropdown()
        binding.targetHostInput.enableFullDropdown()
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
        binding.targetHostInput.doAfterTextChanged {
            viewModel.selectHost(it?.toString().orEmpty())
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        (requireActivity() as MainActivity).refreshFromUi()
    }

    private fun render(state: SessionState) {
        binding.discoveryHint.text = getString(R.string.discovery_hint)
        binding.saveInterfaceButton.isEnabled = state.interfaces.isNotEmpty()
        binding.runSweepButton.isEnabled = state.canContinue && state.rootGranted && !state.isScanning
        binding.openTargetButton.isEnabled = state.rootGranted && state.selectedHostAddress.isNotBlank()
        binding.selectedTargetValue.text = if (state.selectedHostAddress.isBlank()) {
            getString(R.string.discovery_no_target_selected)
        } else {
            getString(R.string.discovery_selected_target, state.selectedHostAddress)
        }

        binding.preferredInterfaceInput.setAdapter(
            NonFilteringStringAdapter(
                requireContext(),
                state.interfaces.map { it.name }
            )
        )
        binding.preferredInterfaceInput.isEnabled = state.rootGranted && state.interfaces.isNotEmpty()
        if (binding.preferredInterfaceInput.text?.toString() != state.preferredInterfaceName) {
            binding.preferredInterfaceInput.setText(state.preferredInterfaceName, false)
        }

        // Live progress while scanning; afterwards (and on a persisted restore) the scanned/found
        // tally. Hidden until the first sweep has produced a count.
        val statsText = when {
            state.isScanning -> state.scanSummary
            state.scannedHostCount > 0 -> getString(
                R.string.discovery_scan_stats,
                state.scannedHostCount,
                state.responsiveTargetResults.size
            )
            else -> ""
        }
        binding.sweepStatsValue.visibility = if (statsText.isBlank()) View.GONE else View.VISIBLE
        binding.sweepStatsValue.text = statsText
        binding.targetsEmptyValue.text = if (state.responsiveTargetResults.isEmpty()) {
            getString(R.string.discovery_no_targets)
        } else {
            ""
        }
        renderResponsiveTargets(state)

        binding.targetHostInput.setAdapter(
            NonFilteringStringAdapter(
                requireContext(),
                state.responsiveHosts
            )
        )
        if (binding.targetHostInput.text?.toString() != state.selectedHostAddress) {
            binding.targetHostInput.setText(state.selectedHostAddress, false)
        }
        binding.targetHostInput.isEnabled = state.rootGranted
    }

    private fun renderResponsiveTargets(state: SessionState) {
        binding.responsiveTargetsContainer.removeAllViews()
        state.responsiveTargetResults.forEach { target ->
            val itemBinding = ItemResponsiveTargetBinding.inflate(layoutInflater, binding.responsiveTargetsContainer, false)
            itemBinding.hostAddressValue.text = target.hostAddress
            itemBinding.hostFindingValue.text = target.finding

            val vendor = target.vendor
            itemBinding.hostVendorValue.visibility = if (vendor.isNullOrBlank()) View.GONE else View.VISIBLE
            itemBinding.hostVendorValue.text = vendor.orEmpty()

            val mac = target.macAddress
            itemBinding.hostMacValue.visibility = if (mac.isNullOrBlank()) View.GONE else View.VISIBLE
            itemBinding.hostMacValue.text = if (mac.isNullOrBlank()) "" else getString(R.string.host_mac_label, mac)

            val osInfo = target.osInfo
            itemBinding.hostOsValue.visibility = if (osInfo.isNullOrBlank()) View.GONE else View.VISIBLE
            itemBinding.hostOsValue.text = if (osInfo.isNullOrBlank()) "" else getString(R.string.host_os_label, osInfo)

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
