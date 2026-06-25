package org.fsploit.android.data.settings

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts individual sensitive strings (e.g. the saved MSF-RPC password) with an AES-256/GCM key
 * held in the Android Keystore, so secrets are not written to [android.content.SharedPreferences] in
 * plaintext. This is the replacement for the deprecated `androidx.security` EncryptedSharedPreferences.
 *
 * The keystore can fail on unusual ROMs or after a key corruption, so both [encrypt] and [decrypt]
 * degrade gracefully (returning the value unchanged) instead of throwing — the caller never crashes
 * just because crypto is unavailable. Ciphertext is tagged with [PREFIX] so [decrypt] can tell an
 * encrypted value apart from a plaintext default or a value left over from an older build.
 */
internal class CredentialCipher {

    private val secretKey: SecretKey? by lazy { runCatching { getOrCreateKey() }.getOrNull() }

    /** Returns `PREFIX + base64(iv || ciphertext)`, or [plaintext] unchanged if encryption is unavailable. */
    fun encrypt(plaintext: String): String {
        val key = secretKey ?: return plaintext
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
            val combined = ByteArray(1 + iv.size + ciphertext.size)
            combined[0] = iv.size.toByte()
            System.arraycopy(iv, 0, combined, 1, iv.size)
            System.arraycopy(ciphertext, 0, combined, 1 + iv.size, ciphertext.size)
            PREFIX + Base64.encodeToString(combined, Base64.NO_WRAP)
        }.getOrDefault(plaintext)
    }

    /** Reverses [encrypt]. Values without [PREFIX] (plaintext defaults / older builds) are returned as-is. */
    fun decrypt(stored: String): String {
        if (!stored.startsWith(PREFIX)) return stored
        val key = secretKey ?: return stored
        return runCatching {
            val combined = Base64.decode(stored.removePrefix(PREFIX), Base64.NO_WRAP)
            val ivSize = combined[0].toInt()
            val iv = combined.copyOfRange(1, 1 + ivSize)
            val ciphertext = combined.copyOfRange(1 + ivSize, combined.size)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            String(cipher.doFinal(ciphertext), Charsets.UTF_8)
        }.getOrDefault(stored)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "fsploit_credential_key"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val PREFIX = "enc:v1:"
    }
}
