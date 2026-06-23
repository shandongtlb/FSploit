package org.fsploit.android.feature.host

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
import androidx.viewpager2.adapter.FragmentStateAdapter
import com.google.android.material.tabs.TabLayoutMediator
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentHostWorkspaceBinding
import org.fsploit.android.feature.loot.LootFragment
import org.fsploit.android.feature.mitm.MitmFragment
import org.fsploit.android.feature.session.SessionState
import org.fsploit.android.feature.session.SessionViewModel
import org.fsploit.android.feature.target.PortScanFragment
import org.fsploit.android.ui.NonFilteringStringAdapter
import org.fsploit.android.ui.enableFullDropdown

/**
 * Host-centric workspace: a single shared host selector at the top drives three tabs
 * (Ports / MITM / Loot), all scoped to the currently selected host via the shared
 * [SessionViewModel] state. Replaces the old standalone Target Detail + MITM screens.
 */
class HostWorkspaceFragment : Fragment() {

    private var _binding: FragmentHostWorkspaceBinding? = null
    private val binding get() = _binding!!

    private val sessionViewModel: SessionViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentHostWorkspaceBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.targetHostInput.enableFullDropdown()
        binding.targetHostInput.setOnItemClickListener { _, _, position, _ ->
            val selected = binding.targetHostInput.adapter.getItem(position)?.toString().orEmpty()
            sessionViewModel.selectHost(selected)
        }
        binding.targetHostInput.doAfterTextChanged {
            sessionViewModel.selectHost(it?.toString().orEmpty())
        }

        binding.hostPager.adapter = WorkspacePagerAdapter(this)
        TabLayoutMediator(binding.hostTabLayout, binding.hostPager) { tab, position ->
            tab.text = getString(TAB_TITLES[position])
        }.attach()

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                sessionViewModel.uiState.collect(::renderHeader)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        (requireActivity() as MainActivity).refreshFromUi()
    }

    private fun renderHeader(state: SessionState) {
        binding.targetHostInput.setAdapter(
            NonFilteringStringAdapter(requireContext(), state.responsiveHosts)
        )
        binding.targetHostInput.isEnabled = state.rootGranted
        if (binding.targetHostInput.text?.toString() != state.selectedHostAddress) {
            binding.targetHostInput.setText(state.selectedHostAddress, false)
        }
        binding.selectedTargetValue.text = if (state.selectedHostAddress.isBlank()) {
            getString(R.string.discovery_no_target_selected)
        } else {
            getString(R.string.discovery_selected_target, state.selectedHostAddress)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        binding.hostPager.adapter = null
        _binding = null
    }

    private class WorkspacePagerAdapter(fragment: Fragment) : FragmentStateAdapter(fragment) {
        override fun getItemCount(): Int = TAB_TITLES.size

        override fun createFragment(position: Int): Fragment = when (position) {
            0 -> PortScanFragment()
            1 -> MitmFragment()
            else -> LootFragment()
        }
    }

    companion object {
        private val TAB_TITLES = intArrayOf(
            R.string.host_tab_ports,
            R.string.nav_mitm,
            R.string.loot_tab_title
        )
    }
}
