package org.fsploit.android.feature.msf

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.widget.doAfterTextChanged
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.textfield.TextInputEditText
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentMsfOverviewBinding
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.ui.bindCollapsible
import org.fsploit.android.ui.setStatusDot

/**
 * Overview/Connection tab of the MSF workspace: root/shell status, push-target handoff, refresh,
 * versions and the RPC endpoint config. Shares [MsfViewModel] + [SessionViewModel] via the
 * activity scope, so it mirrors whatever the workspace header shows.
 */
class MsfOverviewFragment : Fragment() {

    private var _binding: FragmentMsfOverviewBinding? = null
    private val binding get() = _binding!!

    private val sessionViewModel: SessionViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }
    private val viewModel: MsfViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentMsfOverviewBinding.inflate(inflater, container, false)
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
        binding.applyMsgrpcPresetButton.setOnClickListener {
            viewModel.applyMsfMsgrpcPreset()
        }
        binding.saveMsfSettingsButton.setOnClickListener {
            viewModel.saveMsfRpcConfig()
        }
        binding.refreshMsfButton.setOnClickListener {
            viewModel.refreshMsfOverview()
        }

        bindCollapsible(binding.msfVersionsHeader, binding.msfVersionsBody, binding.msfVersionsChevron)
        bindCollapsible(binding.advancedMsfHeader, binding.advancedMsfBody, binding.advancedMsfChevron)

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { viewModel.uiState.collect(::render) }
                launch { sessionViewModel.uiState.collect(::renderSession) }
            }
        }
    }

    private fun renderSession(state: SessionState) {
        binding.rootGateValue.text = state.rootGateSummary
        binding.shellSummaryValue.text = state.shellSummary
        binding.dotMsfRoot.setStatusDot(state.rootGranted)
        binding.dotMsfShell.setStatusDot(state.shellAvailable)
    }

    private fun render(state: MsfUiState) {
        binding.msfVersionValue.text = state.msfFrameworkVersion.ifBlank {
            getString(R.string.msf_value_unknown)
        }
        binding.msfRubyValue.text = state.msfRubyVersion.ifBlank {
            getString(R.string.msf_value_unknown)
        }
        binding.msfApiValue.text = state.msfApiVersion.ifBlank {
            getString(R.string.msf_value_unknown)
        }
        syncInput(binding.msfHostInput, state.msfRpcConfig.host)
        syncInput(binding.msfPortInput, state.msfRpcConfig.port.toString())
        syncInput(binding.msfUsernameInput, state.msfRpcConfig.username)
        syncInput(binding.msfPasswordInput, state.msfRpcConfig.password)
        if (binding.msfUseSslSwitch.isChecked != state.msfRpcConfig.useSsl) {
            binding.msfUseSslSwitch.isChecked = state.msfRpcConfig.useSsl
        }
        binding.msfSettingsSummaryValue.text = state.msfSettingsSummary

        binding.saveMsfSettingsButton.isEnabled = !state.isSavingMsfRpcConfig
        binding.refreshMsfButton.isEnabled = !state.isRefreshingMsf
    }

    private fun syncInput(input: TextInputEditText, value: String) {
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
