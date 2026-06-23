package org.fsploit.android.feature.loot

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentLootBinding
import org.fsploit.android.domain.model.SniffedCredential

class LootFragment : Fragment() {

    private var _binding: FragmentLootBinding? = null
    private val binding get() = _binding!!

    private val viewModel: LootViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentLootBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.startPolling()
    }

    override fun onPause() {
        super.onPause()
        viewModel.stopPolling()
    }

    private fun render(state: LootUiState) {
        binding.lootSummaryValue.text = state.summary
        binding.lootArtifactValue.text = state.artifactPath.ifBlank { getString(R.string.mitm_none) }
        binding.lootEntriesValue.text = if (state.credentials.isEmpty()) {
            getString(R.string.loot_empty_results)
        } else {
            state.credentials.joinToString(separator = "\n\n") { formatEntry(it) }
        }
    }

    private fun formatEntry(entry: SniffedCredential): String {
        return buildString {
            val header = listOf(entry.timestamp, entry.protocol)
                .filter { it.isNotBlank() }
                .joinToString(" · ")
            if (header.isNotBlank()) {
                append(header)
                append('\n')
            }
            if (entry.username.isNotBlank() || entry.password.isNotBlank()) {
                if (entry.username.isNotBlank()) {
                    append(getString(R.string.loot_field_user))
                    append(": ")
                    append(entry.username)
                    append('\n')
                }
                if (entry.password.isNotBlank()) {
                    append(getString(R.string.loot_field_pass))
                    append(": ")
                    append(entry.password)
                    append('\n')
                }
                append(entry.raw)
            } else {
                append(entry.raw)
            }
        }.trimEnd()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
