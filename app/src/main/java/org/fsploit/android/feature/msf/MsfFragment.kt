package org.fsploit.android.feature.msf

import android.os.Bundle
import android.text.method.HideReturnsTransformationMethod
import android.text.method.PasswordTransformationMethod
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
import org.fsploit.android.databinding.FragmentMsfBinding
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

class MsfFragment : Fragment() {

    private var _binding: FragmentMsfBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by activityViewModels {
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
        binding.msfLaunchCommandInput.doAfterTextChanged {
            viewModel.updateMsfRpcLaunchCommand(it?.toString().orEmpty())
        }
        binding.applyMsgrpcPresetButton.setOnClickListener {
            viewModel.applyMsfMsgrpcPreset()
        }
        binding.applyMsfrpcdPresetButton.setOnClickListener {
            viewModel.applyMsfMsfrpcdPreset()
        }
        binding.saveMsfSettingsButton.setOnClickListener {
            viewModel.saveMsfRpcConfig()
        }
        binding.launchMsfRpcButton.setOnClickListener {
            viewModel.launchMsfRpcCommand()
        }
        binding.togglePasswordButton.setOnClickListener {
            val showingPassword = binding.msfPasswordInput.transformationMethod == HideReturnsTransformationMethod.getInstance()
            binding.msfPasswordInput.transformationMethod = if (showingPassword) {
                PasswordTransformationMethod.getInstance()
            } else {
                HideReturnsTransformationMethod.getInstance()
            }
            binding.msfPasswordInput.setSelection(binding.msfPasswordInput.text?.length ?: 0)
            binding.togglePasswordButton.text = getString(
                if (showingPassword) {
                    R.string.msf_show_password
                } else {
                    R.string.msf_hide_password
                }
            )
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
        binding.rootGateValue.text = state.rootGateSummary
        binding.shellSummaryValue.text = state.shellSummary
        binding.msfSummaryValue.text = state.msfSummary
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
        syncInput(binding.msfLaunchCommandInput, state.msfRpcConfig.launchCommand)
        if (binding.msfUseSslSwitch.isChecked != state.msfRpcConfig.useSsl) {
            binding.msfUseSslSwitch.isChecked = state.msfRpcConfig.useSsl
        }
        binding.msfSettingsSummaryValue.text = state.msfSettingsSummary
        binding.msfLaunchSummaryValue.text = state.msfLaunchSummary
        binding.msfLaunchOutputValue.text = state.msfLaunchOutput.ifBlank {
            getString(R.string.msf_launch_output_empty)
        }
        binding.saveMsfSettingsButton.isEnabled = !state.isSavingMsfRpcConfig
        binding.launchMsfRpcButton.isEnabled = state.rootGranted && !state.isLaunchingMsfRpc
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
