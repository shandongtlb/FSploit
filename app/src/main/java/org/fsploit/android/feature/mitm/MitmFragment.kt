package org.fsploit.android.feature.mitm

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
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentMitmBinding
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

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

        binding.targetHostInput.setOnItemClickListener { _, _, position, _ ->
            val selected = binding.targetHostInput.adapter.getItem(position)?.toString().orEmpty()
            viewModel.selectHost(selected)
        }
        binding.blockConnectionButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.blockSelectedHost()
        }
        binding.unblockConnectionButton.setOnClickListener {
            viewModel.selectHost(binding.targetHostInput.text?.toString().orEmpty())
            viewModel.unblockSelectedHost()
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
        binding.rootGateValue.text = state.rootGateSummary
        binding.mitmSummaryValue.text = state.mitmSummary
        binding.iptablesValue.text = yesNo(state.iptablesAvailable)
        binding.tcpdumpValue.text = yesNo(state.tcpdumpAvailable)
        binding.caStoreValue.text = yesNo(state.certificateStoreAccessible)
        binding.selectedTargetValue.text = if (state.selectedHostAddress.isBlank()) {
            getString(R.string.discovery_no_target_selected)
        } else {
            getString(R.string.discovery_selected_target, state.selectedHostAddress)
        }
        binding.currentBlockValue.text = if (state.blockedHostAddress.isBlank()) {
            getString(R.string.block_none)
        } else {
            getString(R.string.block_current_target, state.blockedHostAddress)
        }
        binding.connectionBlockSummaryValue.text = state.connectionBlockSummary
        binding.blockConnectionButton.isEnabled =
            state.rootGranted && state.selectedHostAddress.isNotBlank() && !state.isBlockingConnection
        binding.unblockConnectionButton.isEnabled =
            state.rootGranted && state.selectedHostAddress.isNotBlank() && !state.isBlockingConnection

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

    private fun yesNo(value: Boolean): String {
        return if (value) getString(R.string.mitm_available) else getString(R.string.mitm_unavailable)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
