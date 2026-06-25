package org.fsploit.android.feature.loot

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.launch
import org.fsploit.android.MainActivity
import org.fsploit.android.R
import org.fsploit.android.databinding.FragmentLootBinding
import org.fsploit.android.domain.model.PcapAnalysis
import org.fsploit.android.domain.model.PcapEngine
import org.fsploit.android.domain.model.SniffedCredential
import org.fsploit.android.ui.bindCollapsible

class LootFragment : Fragment() {

    private var _binding: FragmentLootBinding? = null
    private val binding get() = _binding!!

    private val viewModel: LootViewModel by activityViewModels {
        (requireActivity() as MainActivity).viewModelFactory
    }

    private val importKeylogLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) handleKeylogPicked(uri)
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
        bindCollapsible(binding.pcapPacketsHeader, binding.pcapPacketsValue, binding.pcapPacketsChevron)
        binding.pcapImportKeyButton.setOnClickListener {
            importKeylogLauncher.launch(arrayOf("*/*"))
        }
        binding.pcapClearKeyButton.setOnClickListener {
            viewModel.clearKeylog()
        }
        binding.lootClearButton.setOnClickListener {
            viewModel.clearLoot()
        }
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
        renderPcap(state.pcap)
        binding.pcapKeyValue.text = if (state.keylogName.isBlank()) {
            getString(R.string.loot_pcap_key_none)
        } else {
            getString(R.string.loot_pcap_key_imported, state.keylogName)
        }
        binding.pcapClearKeyButton.isEnabled = state.keylogName.isNotBlank()

        // Offer manual clearing whenever there is captured loot on screen.
        val hasLoot = state.pcap != null || state.credentials.isNotEmpty() || state.stopped
        binding.lootClearButton.visibility = if (hasLoot) View.VISIBLE else View.GONE
    }

    private fun handleKeylogPicked(uri: Uri) {
        val copied = copyKeylogIntoStorage(uri)
        if (copied == null) {
            Toast.makeText(requireContext(), R.string.loot_pcap_key_import_failed, Toast.LENGTH_SHORT).show()
            return
        }
        viewModel.setKeylog(copied.first, copied.second)
    }

    /** Copies the picked keylog into app storage so tshark can later read it as root. */
    private fun copyKeylogIntoStorage(uri: Uri): Pair<String, String>? {
        return try {
            val displayName = queryDisplayName(uri)
            val safeName = displayName.replace(Regex("[^A-Za-z0-9._-]"), "_").ifBlank { "keylog.txt" }
            val dir = java.io.File(requireContext().filesDir, "mitm/keylog").apply { mkdirs() }
            val dest = java.io.File(dir, safeName)
            val ok = requireContext().contentResolver.openInputStream(uri)?.use { input ->
                dest.outputStream().use { output -> input.copyTo(output) }
                true
            } ?: false
            if (ok) dest.absolutePath to displayName else null
        } catch (_: Exception) {
            null
        }
    }

    private fun queryDisplayName(uri: Uri): String {
        requireContext().contentResolver
            .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (index >= 0 && cursor.moveToFirst()) {
                    cursor.getString(index)?.let { return it }
                }
            }
        return uri.lastPathSegment?.substringAfterLast('/').orEmpty().ifBlank { "keylog.txt" }
    }

    private fun renderPcap(pcap: PcapAnalysis?) {
        if (pcap == null) {
            binding.pcapCard.visibility = View.GONE
            return
        }
        binding.pcapCard.visibility = View.VISIBLE

        val engineLabel = when {
            pcap.engine == PcapEngine.TSHARK && pcap.decrypted -> getString(R.string.loot_pcap_engine_tshark_decrypted)
            pcap.engine == PcapEngine.TSHARK -> getString(R.string.loot_pcap_engine_tshark)
            else -> getString(R.string.loot_pcap_engine_kotlin)
        }
        binding.pcapSummaryValue.text = if (pcap.note.isBlank()) {
            engineLabel + "\n" + pcap.summaryOrEmpty()
        } else {
            engineLabel + "\n" + pcap.summaryOrEmpty() + "\n" + pcap.note
        }

        binding.pcapFlowsValue.text = if (pcap.flows.isEmpty()) {
            getString(R.string.loot_pcap_empty)
        } else {
            pcap.flows.joinToString(separator = "\n") { f ->
                val proto = f.proto.padEnd(5)
                val a = if (f.srcPort > 0) "${f.src}:${f.srcPort}" else f.src
                val b = if (f.dstPort > 0) "${f.dst}:${f.dstPort}" else f.dst
                "$proto $a ⇄ $b  ${f.packets}pkt ${formatBytes(f.bytes)}"
            }
        }

        binding.pcapHttpValue.text = if (pcap.http.isEmpty()) {
            getString(R.string.loot_pcap_http_empty)
        } else {
            pcap.http.joinToString(separator = "\n") { it.summaryLine }
        }

        binding.pcapPacketsValue.text = if (pcap.packets.isEmpty()) {
            getString(R.string.loot_pcap_empty)
        } else {
            pcap.packets.joinToString(separator = "\n") { p ->
                val t = "%.3f".format(p.tsMs / 1000.0)
                "$t  ${p.proto.padEnd(5)} ${p.src} → ${p.dst}  ${p.length}B  ${p.info}"
            }
        }
    }

    private fun PcapAnalysis.summaryOrEmpty(): String =
        if (available) {
            getString(R.string.loot_pcap_summary, totalPackets, flows.size, http.size)
        } else {
            ""
        }

    private fun formatBytes(bytes: Long): String = when {
        bytes >= 1_048_576 -> "%.1fMB".format(bytes / 1_048_576.0)
        bytes >= 1024 -> "%.1fKB".format(bytes / 1024.0)
        else -> "${bytes}B"
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
