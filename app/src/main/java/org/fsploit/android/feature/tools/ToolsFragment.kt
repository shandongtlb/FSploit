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
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentToolsBinding
import org.fsploit.android.feature.home.HomeUiState
import org.fsploit.android.feature.home.HomeViewModel

class ToolsFragment : Fragment() {

    private var _binding: FragmentToolsBinding? = null
    private val binding get() = _binding!!

    private val viewModel: HomeViewModel by activityViewModels {
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
        binding.presetIdButton.setOnClickListener {
            viewModel.applyShellPreset("id")
        }
        binding.presetIpButton.setOnClickListener {
            viewModel.applyShellPreset("ip addr show")
        }
        binding.presetIptablesButton.setOnClickListener {
            viewModel.applyShellPreset("iptables -L -n")
        }
        binding.presetTcpdumpButton.setOnClickListener {
            viewModel.applyShellPreset("tcpdump --version")
        }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(androidx.lifecycle.Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: HomeUiState) {
        binding.shellSummaryValue.text = state.shellSummary
        if (binding.commandInput.text?.toString() != state.shellCommandInput) {
            binding.commandInput.setText(state.shellCommandInput)
            binding.commandInput.setSelection(binding.commandInput.text?.length ?: 0)
        }
        if (binding.runAsRootSwitch.isChecked != state.shellRunAsRoot) {
            binding.runAsRootSwitch.isChecked = state.shellRunAsRoot
        }
        binding.runCommandButton.isEnabled = !state.isExecutingShell
        binding.commandStatusValue.text = state.shellExecutionSummary
        binding.commandOutputValue.text = state.shellExecutionOutput
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
