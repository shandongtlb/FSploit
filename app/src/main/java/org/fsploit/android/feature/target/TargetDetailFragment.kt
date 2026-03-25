package org.fsploit.android.feature.target

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentTargetDetailBinding
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel
import org.fsploit.android.feature.target.PortResultFilter

class TargetDetailFragment : Fragment() {

    private var _binding: FragmentTargetDetailBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentTargetDetailBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.targetHostInput.setOnItemClickListener { _, _, position, _ ->
            val selected = binding.targetHostInput.adapter.getItem(position)?.toString().orEmpty()
            viewModel.selectHost(selected)
        }
        binding.portSpecInput.doAfterTextChanged {
            viewModel.updatePortSpec(it?.toString().orEmpty())
        }
        binding.timeoutInput.doAfterTextChanged {
            viewModel.updateConnectTimeout(it?.toString().orEmpty())
        }
        binding.parallelismInput.doAfterTextChanged {
            viewModel.updateParallelism(it?.toString().orEmpty())
        }
        binding.portFilterGroup.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) {
                return@addOnButtonCheckedListener
            }
            val filter = when (checkedId) {
                R.id.filterOpenButton -> PortResultFilter.OPEN
                R.id.filterClosedButton -> PortResultFilter.CLOSED
                R.id.filterFilteredButton -> PortResultFilter.FILTERED
                else -> PortResultFilter.ALL
            }
            viewModel.selectPortResultFilter(filter)
        }
        binding.runPortScanButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.runPortScan()
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
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
        if (binding.portSpecInput.text?.toString() != state.portSpec) {
            binding.portSpecInput.setText(state.portSpec)
            binding.portSpecInput.setSelection(binding.portSpecInput.text?.length ?: 0)
        }
        if (binding.timeoutInput.text?.toString() != state.connectTimeoutMs) {
            binding.timeoutInput.setText(state.connectTimeoutMs)
            binding.timeoutInput.setSelection(binding.timeoutInput.text?.length ?: 0)
        }
        if (binding.parallelismInput.text?.toString() != state.parallelism) {
            binding.parallelismInput.setText(state.parallelism)
            binding.parallelismInput.setSelection(binding.parallelismInput.text?.length ?: 0)
        }

        binding.targetSummaryValue.text = if (state.selectedHostAddress.isBlank()) {
            getString(R.string.port_scan_no_selected_host)
        } else {
            getString(R.string.target_detail_summary, state.selectedHostAddress)
        }
        val checkedFilterButton = when (state.selectedPortResultFilter) {
            PortResultFilter.ALL -> R.id.filterAllButton
            PortResultFilter.OPEN -> R.id.filterOpenButton
            PortResultFilter.CLOSED -> R.id.filterClosedButton
            PortResultFilter.FILTERED -> R.id.filterFilteredButton
        }
        if (binding.portFilterGroup.checkedButtonId != checkedFilterButton) {
            binding.portFilterGroup.check(checkedFilterButton)
        }
        binding.runPortScanButton.isEnabled = state.selectedHostAddress.isNotBlank() && !state.isPortScanning
        binding.portScanSummaryValue.text = state.portScanSummary
        val filteredResults = state.scannedPortResults.filter { result ->
            when (state.selectedPortResultFilter) {
                PortResultFilter.ALL -> true
                PortResultFilter.OPEN -> result.state == org.fsploit.android.domain.model.PortState.OPEN
                PortResultFilter.CLOSED -> result.state == org.fsploit.android.domain.model.PortState.CLOSED
                PortResultFilter.FILTERED -> result.state == org.fsploit.android.domain.model.PortState.FILTERED
            }
        }
        binding.portScanResultsValue.text = if (filteredResults.isEmpty()) {
            if (state.responsiveHosts.isEmpty()) {
                getString(R.string.no_target_hosts)
            } else if (state.scannedPortResults.isNotEmpty()) {
                getString(R.string.no_port_results_for_filter)
            } else {
                getString(R.string.no_port_scan_results)
            }
        } else {
            filteredResults.joinToString(separator = "\n") { result ->
                "${result.port.toString().padStart(5, ' ')}  ${result.protocol.padEnd(9, ' ')}  ${portStateLabel(result.state).padEnd(9, ' ')}  ${result.note}"
            }
        }
    }

    private fun portStateLabel(state: org.fsploit.android.domain.model.PortState): String {
        return when (state) {
            org.fsploit.android.domain.model.PortState.OPEN -> getString(R.string.port_state_open)
            org.fsploit.android.domain.model.PortState.CLOSED -> getString(R.string.port_state_closed)
            org.fsploit.android.domain.model.PortState.FILTERED -> getString(R.string.port_state_filtered)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
