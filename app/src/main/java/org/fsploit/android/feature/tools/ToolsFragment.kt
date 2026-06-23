package org.fsploit.android.feature.tools

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
import org.fsploit.android.core.ShellTaskPreset
import org.fsploit.android.databinding.FragmentToolsBinding
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.ui.setStatusDot

class ToolsFragment : Fragment() {

    private var _binding: FragmentToolsBinding? = null
    private val binding get() = _binding!!

    private val sessionViewModel: SessionViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }
    private val viewModel: ToolsViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentToolsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.commandInput.doAfterTextChanged {
            viewModel.updateShellCommand(it?.toString().orEmpty())
        }
        binding.runAsRootSwitch.setOnCheckedChangeListener { _, isChecked ->
            viewModel.updateShellRunAsRoot(isChecked)
        }
        binding.runCommandButton.setOnClickListener {
            viewModel.runShellCommand()
        }
        binding.presetInterfacesButton.setOnClickListener {
            viewModel.applyShellTaskPreset(ShellTaskPreset.NETWORK_INTERFACES)
        }
        binding.presetArpButton.setOnClickListener {
            viewModel.applyShellTaskPreset(ShellTaskPreset.ARP_NEIGHBORS)
        }
        binding.presetIptablesButton.setOnClickListener {
            viewModel.applyShellTaskPreset(ShellTaskPreset.IPTABLES_RULES)
        }
        binding.presetTcpdumpButton.setOnClickListener {
            viewModel.applyShellTaskPreset(ShellTaskPreset.TCPDUMP_VERSION)
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                launch { viewModel.uiState.collect(::render) }
                launch { sessionViewModel.uiState.collect(::renderSession) }
            }
        }
    }

    private fun renderSession(state: SessionState) {
        binding.shellSummaryValue.text = state.shellSummary
        binding.dotShellTools.setStatusDot(state.rootGranted)
        binding.runAsRootSwitch.isEnabled = state.rootGranted
        binding.presetInterfacesButton.isEnabled = state.rootGranted
        binding.presetArpButton.isEnabled = state.rootGranted
        binding.presetIptablesButton.isEnabled = state.rootGranted
        binding.presetTcpdumpButton.isEnabled = state.rootGranted
        binding.runCommandButton.isEnabled = state.rootGranted && !viewModel.uiState.value.isExecutingShell
    }

    private fun render(state: ToolsUiState) {
        binding.selectedTaskLabelValue.text = state.selectedShellTaskLabel
        binding.selectedTaskDescriptionValue.text = state.selectedShellTaskDescription
        if (binding.commandInput.text?.toString() != state.shellCommandInput) {
            binding.commandInput.setText(state.shellCommandInput)
            binding.commandInput.setSelection(binding.commandInput.text?.length ?: 0)
        }
        if (binding.runAsRootSwitch.isChecked != state.shellRunAsRoot) {
            binding.runAsRootSwitch.isChecked = state.shellRunAsRoot
        }
        binding.runCommandButton.isEnabled = sessionViewModel.uiState.value.rootGranted && !state.isExecutingShell
        binding.commandStatusValue.text = state.shellExecutionSummary
        binding.commandOutputValue.text = state.shellExecutionOutput
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
