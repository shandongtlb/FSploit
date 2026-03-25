package org.fsploit.android.data.mitm

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.fsploit.android.data.settings.AppPreferencesRepository
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

class BettercapPackageManager(
    context: Context,
    private val preferencesRepository: AppPreferencesRepository
) {
    private val appContext = context.applicationContext
    private val installDirectory = File(appContext.filesDir, "toolchain/bettercap")
    private val managedBinaryFile = File(installDirectory, BETTERCAP_FILE_NAME)
    private val libusbFile = File(installDirectory, LIBUSB_FILE_NAME)
    private val libusbCompatFile = File(installDirectory, LIBUSB_COMPAT_FILE_NAME)

    fun isManagedPackageInstalled(): Boolean {
        return requiredFiles().all { it.isFile && it.length() > 0L }
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
        val managedPath = managedBinaryFile.absolutePath
        if (config.bettercapPath == managedPath) {
            return false
        }
        preferencesRepository.setMitmToolchainConfig(config.copy(bettercapPath = managedPath))
        return true
    }

    suspend fun downloadManagedPackage(): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            if (!installDirectory.exists() && !installDirectory.mkdirs()) {
                throw IOException("Failed to create ${installDirectory.absolutePath}")
            }
            downloadToFile(BETTERCAP_URL, managedBinaryFile)
            downloadToFile(LIBUSB_URL, libusbFile)
            runCatching {
                downloadToFile(LIBUSB_COMPAT_URL, libusbCompatFile)
            }.getOrElse {
                libusbFile.copyTo(libusbCompatFile, overwrite = true)
            }

            if (!managedBinaryFile.setExecutable(true, false)) {
                throw IOException("Failed to mark bettercap as executable")
            }
            managedBinaryFile.setReadable(true, false)
            libusbFile.setReadable(true, false)
            libusbCompatFile.setReadable(true, false)
            syncInstalledBinaryPath(force = true)
            managedBinaryFile.absolutePath
        }
    }

    private fun requiredFiles(): List<File> {
        return listOf(managedBinaryFile, libusbFile, libusbCompatFile)
    }

    private fun prefersManagedBinary(config: org.fsploit.android.domain.model.MitmToolchainConfig): Boolean {
        val configuredPath = config.bettercapPath.trim()
        return configuredPath.isEmpty() ||
            configuredPath == DEFAULT_BETTERCAP_COMMAND ||
            configuredPath == managedBinaryFile.absolutePath ||
            configuredPath.startsWith(installDirectory.absolutePath)
    }

    private fun downloadToFile(url: String, destination: File) {
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
                tempFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            if (tempFile.length() == 0L) {
                throw IOException("Downloaded empty file: ${destination.name}")
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

    companion object {
        private const val DEFAULT_BETTERCAP_COMMAND = "bettercap"
        private const val BETTERCAP_FILE_NAME = "bettercap"
        private const val LIBUSB_FILE_NAME = "libusb1.0.so"
        private const val LIBUSB_COMPAT_FILE_NAME = "libusb-1.0.so"
        private const val CONNECT_TIMEOUT_MS = 15000
        private const val READ_TIMEOUT_MS = 30000

        private const val BASE_RAW_URL =
            "https://raw.githubusercontent.com/shandongtlb/bettercap-android/main"
        private const val BETTERCAP_URL = "$BASE_RAW_URL/$BETTERCAP_FILE_NAME"
        private const val LIBUSB_URL = "$BASE_RAW_URL/$LIBUSB_FILE_NAME"
        private const val LIBUSB_COMPAT_URL = "$BASE_RAW_URL/$LIBUSB_COMPAT_FILE_NAME"
    }
}
