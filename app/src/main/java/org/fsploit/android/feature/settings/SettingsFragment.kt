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
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

class SettingsFragment : Fragment() {

    private var _binding: FragmentSettingsBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by activityViewModels {
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

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
        binding.languageValue.text = getString(R.string.language_follow_system)
        binding.interfaceValue.text = state.preferredInterfaceName.ifBlank {
            getString(R.string.settings_not_configured)
        }
        binding.portProfileValue.text = getString(
            R.string.settings_port_profile_value,
            state.portSpec.ifBlank { getString(R.string.settings_not_configured) },
            state.connectTimeoutMs.ifBlank { "-" },
            state.parallelism.ifBlank { "-" }
        )
        binding.mitmToolchainValue.text = getString(
            R.string.settings_mitm_toolchain_value,
            state.mitmToolchainConfig.bettercapPath.ifBlank { getString(R.string.settings_not_configured) },
            state.mitmToolchainConfig.tcpdumpPath.ifBlank { getString(R.string.settings_not_configured) },
            state.mitmToolchainConfig.mitmdumpPath.ifBlank { getString(R.string.settings_not_configured) },
            state.mitmToolchainConfig.httpRedirectPort
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
