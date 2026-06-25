package org.fsploit.android.data.mitm

import android.content.Context
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MitmToolchainConfig
import java.io.File
import java.io.IOException

/**
 * Managed installer for the native Android nmap package — same mechanism as
 * [BettercapPackageManager]: a self-hosted arm64 tarball that ships the `nmap` binary plus the
 * full data files (`nmap-services`, `nmap-service-probes`, `nmap-os-db`, NSE scripts) and any
 * bundled `.so` dependencies. The whole tree installs under `filesDir/toolchain/nmap`, which is
 * passed to nmap at runtime via `--datadir` / `LD_LIBRARY_PATH` (see `NmapScanner`).
 */
class NmapPackageManager(
    context: Context,
    preferencesRepository: AppPreferencesRepository
) : ManagedArchivePackageManager(context, preferencesRepository) {
    override val installDirectory = File(appContext.filesDir, "toolchain/nmap")
    override val managedExecutable = File(installDirectory, NMAP_FILE_NAME)
    override val archiveUrl = NMAP_ARCHIVE_URL
    override val archiveSha256 = NMAP_ARCHIVE_SHA256
    override val defaultCommand = DEFAULT_NMAP_COMMAND
    override val displayName = "nmap"

    /** Absolute path of the installed tree, passed to nmap as `--datadir` / `LD_LIBRARY_PATH`. */
    val installRootPath: String get() = installDirectory.absolutePath

    override fun configuredPath(config: MitmToolchainConfig): String = config.nmapPath.trim()

    override fun updateConfig(config: MitmToolchainConfig, managedPath: String): MitmToolchainConfig {
        return config.copy(nmapPath = managedPath)
    }

    override fun requiredFiles(root: File): List<File> {
        // The binary plus the data files a fully-functional nmap cannot run without.
        return listOf(
            File(root, NMAP_FILE_NAME),
            File(root, "nmap-services"),
            File(root, "nmap-service-probes"),
            File(root, "nmap-os-db")
        )
    }

    override fun locatePayloadRoot(extractedDirectory: File): File {
        return findFirstFile(extractedDirectory) { it.name == NMAP_FILE_NAME }
            ?.parentFile
            ?: throw IOException("Failed to locate extracted nmap payload")
    }

    override fun finalizeInstalledTree(root: File) {
        markTreeReadable(root)
        markExecutable(File(root, NMAP_FILE_NAME))
        // Match both `lib*.so` and versioned `lib*.so.1` / `lib*.so.5.4` (File.extension would only
        // catch the former). Shared libs only strictly need read perms, but mark +x to be safe.
        root.walkTopDown()
            .filter { it.isFile && (it.name.endsWith(".so") || it.name.contains(".so.")) }
            .forEach(::markExecutable)
    }

    companion object {
        private const val DEFAULT_NMAP_COMMAND = "nmap"
        private const val NMAP_FILE_NAME = "nmap"

        private const val NMAP_ARCHIVE_URL =
            "https://github.com/shandongtlb/nmap-android/releases/download/V0/nmap-android-arm64-package.tar.gz"
        private val NMAP_ARCHIVE_SHA256: String? =
            "2ce3117ac757d5d36f2aaad99c94f385852cd6e5740c28675b80987773630c9d"
    }
}
