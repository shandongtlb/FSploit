package org.fsploit.android.feature.msf

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
import org.fsploit.android.databinding.FragmentMsfSessionsBinding
import org.fsploit.android.ui.enableFullDropdown

/**
 * Sessions tab of the MSF workspace: live session/job listings and stop actions, with the stop
 * dropdowns populated from the live ids so nothing is hand-typed.
 */
class MsfSessionsFragment : Fragment() {

    private var _binding: FragmentMsfSessionsBinding? = null
    private val binding get() = _binding!!

    private val viewModel: MsfViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentMsfSessionsBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.stopSessionButton.setOnClickListener {
            viewModel.stopSession(binding.stopSessionIdInput.text?.toString().orEmpty())
        }
        binding.stopJobButton.setOnClickListener {
            viewModel.stopJob(binding.stopJobIdInput.text?.toString().orEmpty())
        }

        // Stop a session/job by picking its id from the live list — no hand-typed ids.
        binding.stopSessionIdInput.enableFullDropdown()
        binding.stopJobIdInput.enableFullDropdown()

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::render)
            }
        }
    }

    private fun render(state: MsfUiState) {
        binding.msfSessionsValue.text = if (state.msfSessions.isEmpty()) {
            getString(R.string.msf_sessions_empty)
        } else {
            state.msfSessions.joinToString(separator = "\n\n") { session ->
                buildString {
                    append("#")
                    append(session.id)
                    append("  ")
                    append(session.type.ifBlank { getString(R.string.msf_value_unknown) })
                    append('\n')
                    append(getString(R.string.msf_session_target, session.targetHost.ifBlank { "-" }))
                    append('\n')
                    append(getString(R.string.msf_session_peer, session.tunnelPeer.ifBlank { "-" }))
                    append('\n')
                    append(getString(R.string.msf_session_via, session.viaExploit.ifBlank { "-" }))
                    if (session.description.isNotBlank()) {
                        append('\n')
                        append(session.description)
                    }
                }
            }
        }
        binding.msfJobsValue.text = if (state.msfJobs.isEmpty()) {
            getString(R.string.msf_jobs_empty)
        } else {
            state.msfJobs.joinToString(separator = "\n") { job ->
                "#${job.id}  ${job.name.ifBlank { getString(R.string.msf_value_unknown) }}"
            }
        }
        binding.msfActionSummaryValue.text = state.msfActionSummary
        // Stop dropdowns list the live session/job ids — selection over hand-typed numbers.
        binding.stopSessionIdInput.setSimpleItems(state.msfSessions.map { it.id }.toTypedArray())
        binding.stopJobIdInput.setSimpleItems(state.msfJobs.map { it.id }.toTypedArray())

        binding.stopSessionButton.isEnabled = !state.isRunningMsfAction
        binding.stopJobButton.isEnabled = !state.isRunningMsfAction
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
