package org.fsploit.android.feature.msf

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentMsfWorkspaceBinding
import org.fsploit.android.ui.setStatusDot
import org.fsploit.android.ui.showInfoBubble

/**
 * MSF workspace: a persistent RPC-connection header stays visible while three tabs
 * (Overview/Connection · Exploit · Sessions) split what used to be one long scroll, all sharing
 * the same [MsfViewModel] via the activity scope. Mirrors the host workspace layout.
 */
class MsfWorkspaceFragment : Fragment() {

    private var _binding: FragmentMsfWorkspaceBinding? = null
    private val binding get() = _binding!!

    private val viewModel: MsfViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentMsfWorkspaceBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.msfHelpInfo.setOnClickListener {
            showInfoBubble(
                anchor = it,
                body = getString(R.string.msf_help_body),
                copyText = getString(R.string.msf_help_command)
            )
        }

        binding.msfPager.adapter = WorkspacePagerAdapter(this)
        TabLayoutMediator(binding.msfTabLayout, binding.msfPager) { tab, position ->
            tab.text = getString(TAB_TITLES[position])
        }.attach()

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect(::renderHeader)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.refresh()
        (requireActivity() as MainActivity).refreshFromUi()
    }

    private fun renderHeader(state: MsfUiState) {
        binding.dotMsfConnected.setStatusDot(state.msfConnected)
        binding.msfConnectedValue.text = getString(
            if (state.msfConnected) R.string.msf_connected else R.string.msf_disconnected
        )
        binding.msfSummaryValue.text = state.msfSummary
        binding.msfSummaryValue.isVisible = state.msfSummary.isNotBlank()
        binding.msfHelperStatusValue.text = state.helperStatusSummary
        binding.msfHelperStatusValue.isVisible = state.helperStatusSummary.isNotBlank()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        binding.msfPager.adapter = null
        _binding = null
    }

    private class WorkspacePagerAdapter(fragment: Fragment) : FragmentStateAdapter(fragment) {
        override fun getItemCount(): Int = TAB_TITLES.size

        override fun createFragment(position: Int): Fragment = when (position) {
            0 -> MsfOverviewFragment()
            1 -> MsfExploitFragment()
            else -> MsfSessionsFragment()
        }
    }

    companion object {
        private val TAB_TITLES = intArrayOf(
            R.string.msf_tab_overview,
            R.string.msf_tab_exploit,
            R.string.msf_tab_sessions
        )
    }
}
