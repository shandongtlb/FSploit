package org.fsploit.android.data.mitm

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.fsploit.android.data.settings.AppPreferencesRepository
import org.fsploit.android.domain.model.MitmToolchainConfig
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.zip.GZIPInputStream

abstract class ManagedArchivePackageManager(
    context: Context,
    protected val preferencesRepository: AppPreferencesRepository
) {
    protected val appContext = context.applicationContext

    protected abstract val installDirectory: File
    protected abstract val managedExecutable: File
    protected abstract val archiveUrl: String
    protected open val archiveSha256: String? = null
    protected abstract val defaultCommand: String
    protected abstract val displayName: String

    fun isManagedPackageInstalled(): Boolean {
        return requiredFiles(installDirectory).all { it.isFile && it.length() > 0L }
    }

    fun shouldOfferManagedDownload(): Boolean {
        return !isManagedPackageInstalled() && prefersManagedBinary(preferencesRepository.getMitmToolchainConfig())
    }

    fun syncInstalledBinaryPath(force: Boolean = false): Boolean {
        if (!isManagedPackageInstalled()) {
            return false
        }
        val config = preferencesRepository.getMitmToolchainConfig()
        if (!force && !prefersManagedBinary(config)) {
            return false
        }
        val managedPath = managedExecutable.absolutePath
        if (configuredPath(config) == managedPath) {
            return false
        }
        preferencesRepository.setMitmToolchainConfig(updateConfig(config, managedPath))
        return true
    }

    suspend fun downloadManagedPackage(): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            installManagedPackage()
        }
    }

    protected abstract fun configuredPath(config: MitmToolchainConfig): String

    protected abstract fun updateConfig(config: MitmToolchainConfig, managedPath: String): MitmToolchainConfig

    protected abstract fun requiredFiles(root: File): List<File>

    protected abstract fun locatePayloadRoot(extractedDirectory: File): File

    protected open fun finalizeInstalledTree(root: File) {}

    protected fun findFirstFile(root: File, predicate: (File) -> Boolean): File? {
        return root.walkTopDown()
            .firstOrNull { it.isFile && predicate(it) }
    }

    protected fun markTreeReadable(root: File) {
        root.walkTopDown().forEach { file ->
            file.setReadable(true, false)
            if (file.isDirectory) {
                file.setExecutable(true, false)
            }
        }
    }

    protected fun markExecutable(file: File) {
        if (!file.isFile) {
            throw IOException("Missing ${file.absolutePath}")
        }
        if (!file.setExecutable(true, false)) {
            throw IOException("Failed to mark ${file.name} as executable")
        }
        file.setReadable(true, false)
    }

    protected open fun prefersManagedBinary(config: MitmToolchainConfig): Boolean {
        val configuredPath = configuredPath(config).trim()
        return configuredPath.isEmpty() ||
            configuredPath == defaultCommand ||
            configuredPath == managedExecutable.absolutePath ||
            configuredPath.startsWith(installDirectory.absolutePath)
    }

    private fun installManagedPackage(): String {
        val parentDirectory = installDirectory.parentFile
            ?: throw IOException("Missing install parent for $displayName")
        if (!parentDirectory.exists() && !parentDirectory.mkdirs()) {
            throw IOException("Failed to create ${parentDirectory.absolutePath}")
        }

        val stagingDirectory = File(parentDirectory, "${installDirectory.name}.staging")
        val candidateDirectory = File(parentDirectory, "${installDirectory.name}.candidate")
        val backupDirectory = File(parentDirectory, "${installDirectory.name}.backup")
        val archiveFile = File(parentDirectory, "${installDirectory.name}.download.tar.gz")
        deleteIfExists(stagingDirectory)
        deleteIfExists(candidateDirectory)
        deleteIfExists(backupDirectory)
        deleteIfExists(archiveFile)

        try {
            if (!stagingDirectory.mkdirs()) {
                throw IOException("Failed to create ${stagingDirectory.absolutePath}")
            }
            downloadToFile(archiveUrl, archiveFile, archiveSha256)
            extractTarGz(archiveFile, stagingDirectory)

            val payloadRoot = locatePayloadRoot(stagingDirectory)
            moveDirectory(payloadRoot, candidateDirectory)
            finalizeInstalledTree(candidateDirectory)
            validateInstalledTree(candidateDirectory)
            replaceInstallDirectory(candidateDirectory, backupDirectory)

            syncInstalledBinaryPath(force = true)
            return managedExecutable.absolutePath
        } catch (exception: Exception) {
            restoreBackupIfNeeded(backupDirectory)
            throw exception
        } finally {
            deleteIfExists(stagingDirectory)
            deleteIfExists(candidateDirectory)
            deleteIfExists(backupDirectory)
            deleteIfExists(archiveFile)
        }
    }

    private fun validateInstalledTree(root: File) {
        requiredFiles(root).firstOrNull { !it.isFile || it.length() == 0L }?.let { missing ->
            throw IOException("Managed $displayName package is incomplete: ${missing.absolutePath}")
        }
    }

    private fun replaceInstallDirectory(candidateDirectory: File, backupDirectory: File) {
        if (installDirectory.exists()) {
            moveDirectory(installDirectory, backupDirectory)
        }
        try {
            moveDirectory(candidateDirectory, installDirectory)
        } catch (exception: Exception) {
            restoreBackupIfNeeded(backupDirectory)
            throw exception
        }
    }

    private fun restoreBackupIfNeeded(backupDirectory: File) {
        if (!backupDirectory.exists() || installDirectory.exists()) {
            return
        }
        moveDirectory(backupDirectory, installDirectory)
    }

    private fun extractTarGz(archiveFile: File, targetDirectory: File) {
        archiveFile.inputStream().buffered().use { fileInput ->
            GZIPInputStream(fileInput).use { gzipInput ->
                TarArchiveInputStream(gzipInput).use { tarInput ->
                    while (true) {
                        val entry = tarInput.nextEntry as? TarArchiveEntry ?: break
                        val destination = resolveArchivePath(targetDirectory, entry.name)
                        when {
                            entry.isDirectory -> {
                                if (!destination.exists() && !destination.mkdirs()) {
                                    throw IOException("Failed to create ${destination.absolutePath}")
                                }
                            }

                            entry.isSymbolicLink || entry.isLink -> {
                                continue
                            }

                            else -> {
                                val parent = destination.parentFile
                                    ?: throw IOException("Missing parent for ${destination.absolutePath}")
                                if (!parent.exists() && !parent.mkdirs()) {
                                    throw IOException("Failed to create ${parent.absolutePath}")
                                }
                                destination.outputStream().buffered().use { output ->
                                    tarInput.copyTo(output)
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private fun resolveArchivePath(targetDirectory: File, entryName: String): File {
        val normalizedPath = entryName.replace('\\', '/').trimStart('/')
        if (normalizedPath.isEmpty()) {
            throw IOException("Invalid archive entry name")
        }
        val destination = File(targetDirectory, normalizedPath)
        val basePath = targetDirectory.canonicalFile.toPath()
        val destinationPath = destination.canonicalFile.toPath()
        if (!destinationPath.startsWith(basePath)) {
            throw IOException("Archive entry escapes target directory: $entryName")
        }
        return destination
    }

    private fun moveDirectory(source: File, destination: File) {
        val parent = destination.parentFile
            ?: throw IOException("Missing parent for ${destination.absolutePath}")
        if (!parent.exists() && !parent.mkdirs()) {
            throw IOException("Failed to create ${parent.absolutePath}")
        }
        if (source.renameTo(destination)) {
            return
        }
        if (!source.copyRecursively(destination, overwrite = true)) {
            throw IOException("Failed to copy ${source.absolutePath} to ${destination.absolutePath}")
        }
        if (!source.deleteRecursively()) {
            throw IOException("Failed to clean ${source.absolutePath}")
        }
    }

    private fun deleteIfExists(file: File) {
        if (file.exists() && !file.deleteRecursively()) {
            throw IOException("Failed to delete ${file.absolutePath}")
        }
    }

    private fun downloadToFile(url: String, destination: File, expectedSha256: String?) {
        val tempFile = File(destination.parentFile, "${destination.name}.part")
        if (tempFile.exists()) {
            tempFile.delete()
        }

        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = true
            requestMethod = "GET"
        }
        try {
            val responseCode = connection.responseCode
            if (responseCode !in 200..299) {
                throw IOException("HTTP $responseCode while downloading ${destination.name}")
            }
            connection.inputStream.use { input ->
                tempFile.outputStream().buffered().use { output ->
                    input.copyTo(output)
                }
            }
            if (tempFile.length() == 0L) {
                throw IOException("Downloaded empty file: ${destination.name}")
            }
            expectedSha256?.let { expected ->
                val actual = sha256(tempFile)
                if (!actual.equals(expected, ignoreCase = true)) {
                    throw IOException("SHA-256 mismatch for ${destination.name}")
                }
            }
            if (destination.exists() && !destination.delete()) {
                throw IOException("Failed to replace ${destination.absolutePath}")
            }
            if (!tempFile.renameTo(destination)) {
                tempFile.copyTo(destination, overwrite = true)
                tempFile.delete()
            }
        } finally {
            connection.disconnect()
            if (tempFile.exists() && tempFile.length() == 0L) {
                tempFile.delete()
            }
        }
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) {
                    break
                }
                if (read > 0) {
                    digest.update(buffer, 0, read)
                }
            }
        }
        return digest.digest().joinToString("") { "%02X".format(it) }
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 15000
        private const val READ_TIMEOUT_MS = 30000
    }
}
