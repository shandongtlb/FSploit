package org.fsploit.android.feature.overview

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentOverviewBinding
import org.fsploit.android.domain.model.InterfaceCategory
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

class OverviewFragment : Fragment() {

    private var _binding: FragmentOverviewBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentOverviewBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.requestPermissionsButton.setOnClickListener {
            (requireActivity() as MainActivity).requestPermissionsFromUi()
        }
        binding.refreshButton.setOnClickListener {
            (requireActivity() as MainActivity).refreshFromUi()
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
        binding.statusMessage.text = state.statusMessage
        binding.rootGateValue.text = state.rootGateSummary
        binding.permissionSummaryValue.text = state.permissionSummary
        binding.activeTransportValue.text = state.activeTransportLabel
        binding.shellSummaryValue.text = state.shellSummary
        binding.requestPermissionsButton.isEnabled =
            !(requireActivity() as MainActivity).hasAllRequiredPermissionsForUi()
        binding.continueHint.text = if (state.canContinue) {
            getString(R.string.home_ready)
        } else {
            getString(R.string.home_not_ready)
        }

        binding.interfaceListValue.text = if (state.interfaces.isEmpty()) {
            getString(R.string.no_interfaces_found)
        } else {
            state.interfaces.joinToString(separator = "\n\n") { info ->
                val label = when (info.category) {
                    InterfaceCategory.WIFI -> getString(R.string.category_wifi)
                    InterfaceCategory.ETHERNET -> getString(R.string.category_ethernet)
                    InterfaceCategory.USB -> getString(R.string.category_usb)
                    InterfaceCategory.OTHER -> getString(R.string.category_other)
                }
                "$label: ${info.name}\n${info.addresses.joinToString()}"
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
