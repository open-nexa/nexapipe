package com.nexa.pipe

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Seals the credentials this app keeps at rest: TOTP seeds, enrollment tokens
 * and the relay bearer token.
 *
 * The key lives in the Android keystore and never enters the process heap as
 * material, so reading the preferences file — from a backup, a rooted shell or
 * a pulled APK's private data — yields ciphertext that only this installation
 * can open. That is the property the keystore buys and a hard-coded key would
 * not: the app is not shipped with the means to decrypt its own storage.
 *
 * This replaces the `EncryptedSharedPreferences` of `androidx.security`, whose
 * API was deprecated in whole with 1.1.0 and which Google no longer publishes.
 *
 * Values are `AES-256-GCM` with a fresh 12-byte nonce per call, stored
 * alongside the ciphertext. GCM fails closed on tampering, so a corrupted
 * value surfaces as "no credential" rather than as a wrong one.
 */
class SecretStore {
    companion object {
        private const val TAG = "SecretStore"
        private const val ALIAS = "nexapipe_credentials"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val NONCE_BYTES = 12
        private const val TAG_BITS = 128

        /**
         * Marks a value as sealed. Anything without it is plaintext: either a
         * value an older version wrote, or one that could not be sealed at the
         * time it was saved.
         */
        const val MARKER = "v1:"
    }

    private val keyStore: KeyStore? = try {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    } catch (e: Exception) {
        Log.e(TAG, "The keystore is unavailable, credentials will stay in plaintext", e)
        null
    }

    private var cachedKey: SecretKey? = null

    /**
     * Wraps [plain] for storage.
     *
     * Returns [plain] unchanged when there is no key to use. Sealing can only
     * fail on a device whose keystore is broken, and the alternative — refusing
     * to store the credential — would silently disconnect the user from their
     * own endpoint. Losing the ciphertext on such a device is a smaller
     * failure than losing the credential, and the file holding it is excluded
     * from backups either way.
     */
    fun seal(plain: String): String {
        if (plain.isEmpty()) return plain
        val key = key() ?: return plain
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            // No GCMParameterSpec here on purpose: the keystore generates the
            // nonce and refuses one supplied by the caller, which is what
            // keeps two encryptions of the same secret from producing the same
            // bytes. It is then read back off the cipher.
            cipher.init(Cipher.ENCRYPT_MODE, key)
            val nonce = cipher.iv
            val body = cipher.doFinal(plain.toByteArray(Charsets.UTF_8))
            MARKER + Base64.encodeToString(nonce + body, Base64.NO_WRAP)
        } catch (e: GeneralSecurityException) {
            Log.e(TAG, "Could not seal a credential, storing it in plaintext", e)
            plain
        }
    }

    /**
     * Reads back a value written by [seal], or "" if it cannot be read.
     *
     * A value without the marker is returned as it stands. Those are the
     * plaintext credentials older versions left behind, and they are the user's
     * only copy: treating them as absent would lock them out of their
     * endpoints, which is worse than leaving them readable until they are next
     * saved. A sealed value that does not open is treated as absent — the key
     * is gone or the record was damaged, and in both cases there is no
     * credential to be had.
     */
    fun unseal(stored: String?): String {
        val value = stored ?: ""
        if (!value.startsWith(MARKER)) return value
        val key = key() ?: return ""
        return try {
            val packed = Base64.decode(value.removePrefix(MARKER), Base64.DEFAULT)
            if (packed.size <= NONCE_BYTES) {
                Log.w(TAG, "A sealed credential is truncated, treating it as unset")
                return ""
            }
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                key,
                GCMParameterSpec(TAG_BITS, packed, 0, NONCE_BYTES)
            )
            String(cipher.doFinal(packed, NONCE_BYTES, packed.size - NONCE_BYTES), Charsets.UTF_8)
        } catch (e: IllegalArgumentException) {
            Log.w(TAG, "A sealed credential is malformed, treating it as unset")
            ""
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "Could not unseal a credential, treating it as unset")
            ""
        }
    }

    private fun key(): SecretKey? {
        cachedKey?.let { return it }
        val store = keyStore ?: return null
        val resolved = try {
            store.getKey(ALIAS, null) as? SecretKey
        } catch (e: GeneralSecurityException) {
            Log.w(TAG, "The credential key could not be loaded", e)
            null
        } ?: generate()
        cachedKey = resolved
        return resolved
    }

    private fun generate(): SecretKey? = try {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(
                KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    // Deliberately not gated on user authentication: this app
                    // has to reopen its endpoints after a reboot without
                    // anyone present to unlock anything.
                    .build()
            )
            generateKey()
        }
    } catch (e: GeneralSecurityException) {
        Log.e(TAG, "Could not create the credential key", e)
        null
    }
}
