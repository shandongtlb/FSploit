package org.fsploit.android.feature.settings

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
import org.fsploit.android.databinding.FragmentSettingsBinding
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    private val sessionViewModel: SessionViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }
    private val viewModel: SettingsViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentSettingsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.bettercapPathInput.doAfterTextChanged {
            viewModel.updateMitmBettercapPath(it?.toString().orEmpty())
        }
        binding.tcpdumpPathInput.doAfterTextChanged {
            viewModel.updateMitmTcpdumpPath(it?.toString().orEmpty())
        }
        binding.mitmdumpPathInput.doAfterTextChanged {
            viewModel.updateMitmMitmdumpPath(it?.toString().orEmpty())
        }
        binding.httpRedirectPortInput.doAfterTextChanged {
            viewModel.updateMitmHttpRedirectPort(it?.toString().orEmpty())
        }
        binding.saveMitmSettingsButton.setOnClickListener {
            viewModel.saveMitmToolchainConfig()
        }

        binding.languageValue.text = getString(R.string.language_follow_system)

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
        binding.interfaceValue.text = state.preferredInterfaceName.ifBlank {
            getString(R.string.settings_not_configured)
        }
    }

    private fun render(state: SettingsUiState) {
        binding.portProfileValue.text = getString(
            R.string.settings_port_profile_value,
            state.portScanConfig.portSpec.ifBlank { getString(R.string.settings_not_configured) },
            state.portScanConfig.connectTimeoutMs.takeIf { it > 0 }?.toString() ?: "-",
            state.portScanConfig.parallelism.takeIf { it > 0 }?.toString() ?: "-"
        )
        syncInput(binding.bettercapPathInput, state.mitmToolchainConfig.bettercapPath)
        syncInput(binding.tcpdumpPathInput, state.mitmToolchainConfig.tcpdumpPath)
        syncInput(binding.mitmdumpPathInput, state.mitmToolchainConfig.mitmdumpPath)
        syncInput(binding.httpRedirectPortInput, state.mitmToolchainConfig.httpRedirectPort.toString())
        binding.mitmSettingsSummaryValue.text = state.mitmSettingsSummary
        binding.saveMitmSettingsButton.isEnabled = !state.isSavingMitmToolchainConfig
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
