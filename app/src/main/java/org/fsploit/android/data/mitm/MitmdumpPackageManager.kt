package org.fsploit.android.data.mitm

import android.content.Context
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MitmToolchainConfig
import java.io.File
import java.io.IOException

class MitmdumpPackageManager(
    context: Context,
    preferencesRepository: AppPreferencesRepository
) : ManagedArchivePackageManager(context, preferencesRepository) {
    override val installDirectory = File(appContext.filesDir, "toolchain/mitmdump")
    override val managedExecutable = File(installDirectory, "bin/mitmdump")
    override val archiveUrl = MITMDUMP_ARCHIVE_URL
    override val defaultCommand = DEFAULT_MITMDUMP_COMMAND
    override val displayName = "mitmdump"

    override fun configuredPath(config: MitmToolchainConfig): String = config.mitmdumpPath.trim()

    override fun updateConfig(config: MitmToolchainConfig, managedPath: String): MitmToolchainConfig {
        return config.copy(mitmdumpPath = managedPath)
    }

    override fun requiredFiles(root: File): List<File> {
        return listOf(
            File(root, "bin/mitmdump"),
            File(root, "python/bin/python3"),
            File(root, "python/lib/libpython3.14.so")
        )
    }

    override fun locatePayloadRoot(extractedDirectory: File): File {
        return findFirstFile(extractedDirectory) { file ->
            file.name == "mitmdump" &&
                file.parentFile?.name == "bin" &&
                file.parentFile?.parentFile?.let { root ->
                    File(root, "python").isDirectory
                } == true
        }?.parentFile?.parentFile
            ?: throw IOException("Failed to locate extracted mitmdump payload")
    }

    override fun finalizeInstalledTree(root: File) {
        markTreeReadable(root)
        markExecutable(File(root, "bin/mitmdump"))
        markExecutable(File(root, "python/bin/python3"))
        root.walkTopDown()
            .filter { it.isFile && it.extension == "so" }
            .forEach(::markExecutable)
    }

    companion object {
        private const val DEFAULT_MITMDUMP_COMMAND = "mitmdump"
        private const val MITMDUMP_ARCHIVE_URL =
            "https://github.com/shandongtlb/mitmdump-android/releases/download/v0/mitmdump-android-aarch64-bundle.tar.gz"
    }
}
