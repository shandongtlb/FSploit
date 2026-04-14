package org.fsploit.android.data.mitm

import android.content.Context
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MitmToolchainConfig
import java.io.File
import java.io.IOException

class BettercapPackageManager(
    context: Context,
    preferencesRepository: AppPreferencesRepository
): ManagedArchivePackageManager(context, preferencesRepository) {
    override val installDirectory = File(appContext.filesDir, "toolchain/bettercap")
    override val managedExecutable = File(installDirectory, BETTERCAP_FILE_NAME)
    override val archiveUrl = BETTERCAP_ARCHIVE_URL
    override val archiveSha256 = BETTERCAP_ARCHIVE_SHA256
    override val defaultCommand = DEFAULT_BETTERCAP_COMMAND
    override val displayName = "bettercap"

    override fun configuredPath(config: MitmToolchainConfig): String = config.bettercapPath.trim()

    override fun updateConfig(config: MitmToolchainConfig, managedPath: String): MitmToolchainConfig {
        return config.copy(bettercapPath = managedPath)
    }

    override fun requiredFiles(root: File): List<File> {
        return listOf(
            File(root, BETTERCAP_FILE_NAME),
            File(root, LIBUSB_FILE_NAME)
        )
    }

    override fun locatePayloadRoot(extractedDirectory: File): File {
        return findFirstFile(extractedDirectory) { it.name == BETTERCAP_FILE_NAME }
            ?.parentFile
            ?: throw IOException("Failed to locate extracted bettercap payload")
    }

    override fun finalizeInstalledTree(root: File) {
        val primaryLibusb = File(root, LIBUSB_FILE_NAME)
        val compatLibusb = File(root, LIBUSB_COMPAT_FILE_NAME)
        if (!compatLibusb.exists() && primaryLibusb.isFile) {
            primaryLibusb.copyTo(compatLibusb, overwrite = true)
        }
        markTreeReadable(root)
        markExecutable(File(root, BETTERCAP_FILE_NAME))
    }

    companion object {
        private const val DEFAULT_BETTERCAP_COMMAND = "bettercap"
        private const val BETTERCAP_FILE_NAME = "bettercap"
        private const val LIBUSB_FILE_NAME = "libusb1.0.so"
        private const val LIBUSB_COMPAT_FILE_NAME = "libusb-1.0.so"
        private const val BETTERCAP_ARCHIVE_URL =
            "https://github.com/shandongtlb/bettercap-android/releases/download/v0/bettercap-android-arm64-package.tar.gz"
        private const val BETTERCAP_ARCHIVE_SHA256 =
            "E290F3394FD342E96FFD78F7AED0B367BA73A31972B9F0B8DD162521BBE89151"
    }
}
