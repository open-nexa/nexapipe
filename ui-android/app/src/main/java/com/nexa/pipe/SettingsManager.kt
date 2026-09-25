package com.nexa.pipe

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.nexa.pipe.ui.NodeConfig
import com.nexa.pipe.ui.NodeTwoFactor
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString

class SettingsManager(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    // 2FA secrets live in their own prefs file so backup rules can exclude
    // them as a whole; a TOTP seed must never leave the device. The endpoint
    // list itself *is* backed up, so every secret is pulled out of it on save
    // and kept here under its own endpoint ID instead.
    private val secretPrefs: SharedPreferences = context.getSharedPreferences("NexaPipeSecrets", Context.MODE_PRIVATE)
    private val json = Json { ignoreUnknownKeys = true }

    init {
        migrateLegacyTwoFactor()
    }

    companion object {
        private const val TAG = "SettingsManager"
        const val PREFS_NAME = "NexaPipeSettings"
        const val KEY_NODES = "nodes"
        const val KEY_RELAY_MODE = "relay_mode"
        const val KEY_RELAY_URL = "relay_url"
        const val KEY_RELAY_AUTH_TOKEN = "relay_auth_token"
        // Prefix of the per-endpoint secret entries in `secretPrefs`.
        const val SECRET_PREFIX = "two_factor_secret_"
        // Read once by `migrateLegacyTwoFactor` and then deleted: 2FA used to
        // be one app-wide setting, it now belongs to an endpoint.
        const val KEY_2FA_ENABLED = "two_factor_enabled"
        const val KEY_2FA_CLIENT_ID = "two_factor_client_id"
        const val KEY_2FA_SECRET = "two_factor_secret"
        const val KEY_2FA_ALGORITHM = "two_factor_algorithm"
        const val KEY_2FA_MIGRATED = "two_factor_migrated"

        // Language tag of the app UI, e.g. "zh-CN". Empty means "follow the
        // system", which is the default.
        private const val KEY_LANGUAGE = "app_language"

        /**
         * The saved language tag, or "" for "follow the system".
         *
         * A static read on purpose: `attachBaseContext` needs it before a
         * [SettingsManager] — and its 2FA migration — would be worth building.
         */
        @JvmStatic
        fun loadLanguage(context: Context): String =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_LANGUAGE, "") ?: ""

        @JvmStatic
        fun saveLanguage(context: Context, languageTag: String) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_LANGUAGE, languageTag)
                .apply()
        }
    }

    /**
     * Moves the old app-wide 2FA setting onto the endpoints.
     *
     * Such a pair authenticated *every* connection, so the faithful migration
     * is the same credentials on every configured endpoint — from there each
     * one is edited on its own page. Runs at most once. With no endpoint yet
     * there is nothing to attach the credentials to, and they are dropped
     * rather than quietly kept as a setting that still applies to everything.
     */
    private fun migrateLegacyTwoFactor() {
        if (secretPrefs.getBoolean(KEY_2FA_MIGRATED, false)) {
            return
        }
        val legacy = takeLegacyTwoFactor()
        secretPrefs.edit().putBoolean(KEY_2FA_MIGRATED, true).apply()
        if (legacy == null || !legacy.enabled || legacy.clientId.isBlank() || legacy.secret.isBlank()) {
            return
        }
        val nodes = decodeNodes()
        if (nodes.isEmpty()) {
            Log.w(TAG, "Dropped the app-wide 2FA setting: there is no endpoint to attach it to")
            return
        }
        val otp = NodeTwoFactor(
            enabled = true,
            clientId = legacy.clientId,
            secret = legacy.secret,
            algorithm = legacy.algorithm
        )
        saveNodes(nodes.map { node -> node.copy(twoFactor = otp) })
        Log.i(TAG, "Moved the app-wide 2FA setting onto ${nodes.size} endpoint(s)")
    }

    /**
     * Reads the pre-endpoint 2FA setting and deletes it.
     *
     * The oldest versions wrote it to [prefs]; a later migration moved it to
     * [secretPrefs]. Both are checked so an app that skipped a version still
     * gets its credentials migrated.
     */
    private fun takeLegacyTwoFactor(): LegacyTwoFactor? {
        val source = when {
            secretPrefs.contains(KEY_2FA_ENABLED) -> secretPrefs
            prefs.contains(KEY_2FA_ENABLED) -> prefs
            else -> return null
        }
        val legacy = LegacyTwoFactor(
            enabled = source.getBoolean(KEY_2FA_ENABLED, false),
            clientId = source.getString(KEY_2FA_CLIENT_ID, "") ?: "",
            secret = source.getString(KEY_2FA_SECRET, "") ?: "",
            algorithm = source.getString(KEY_2FA_ALGORITHM, "sha1") ?: "sha1"
        )
        source.edit()
            .remove(KEY_2FA_ENABLED)
            .remove(KEY_2FA_CLIENT_ID)
            .remove(KEY_2FA_SECRET)
            .remove(KEY_2FA_ALGORITHM)
            .apply()
        return legacy
    }

    private data class LegacyTwoFactor(
        val enabled: Boolean,
        val clientId: String,
        val secret: String,
        val algorithm: String
    )

    /**
     * Persists the endpoints. The 2FA secret of each endpoint is written to
     * [secretPrefs] and stripped from the list saved in [prefs], so the backed
     * up copy carries the configuration but never a seed.
     */
    fun saveNodes(nodes: List<NodeConfig>) {
        val editor = secretPrefs.edit()
        // A secret outlives its endpoint otherwise: deleting the endpoint
        // would leave the seed behind, and the next endpoint to reuse that ID
        // would inherit it.
        for (key in secretPrefs.all.keys) {
            if (!key.startsWith(SECRET_PREFIX)) continue
            val nodeId = key.removePrefix(SECRET_PREFIX)
            val otp = nodes.firstOrNull { it.nodeId == nodeId }?.twoFactor
            if (otp == null || otp.secret.isBlank()) {
                editor.remove(key)
            }
        }

        val persisted = nodes.map { node ->
            val otp = node.twoFactor
            if (otp == null || otp.secret.isBlank()) {
                node
            } else {
                editor.putString(SECRET_PREFIX + node.nodeId, otp.secret)
                node.copy(twoFactor = otp.copy(secret = ""))
            }
        }
        editor.apply()
        prefs.edit().putString(KEY_NODES, json.encodeToString(persisted)).apply()
    }

    /** Loads the endpoints, re-attaching each 2FA secret from [secretPrefs]. */
    fun loadNodes(): List<NodeConfig> {
        val stored = decodeNodes()
        if (stored.isEmpty()) return stored
        return stored.map { node ->
            val otp = node.twoFactor ?: return@map node
            val secret = secretPrefs.getString(SECRET_PREFIX + node.nodeId, "") ?: ""
            node.copy(twoFactor = otp.copy(secret = secret))
        }
    }

    private fun decodeNodes(): List<NodeConfig> {
        val jsonStr = prefs.getString(KEY_NODES, "")
        if (jsonStr.isNullOrEmpty()) {
            return emptyList()
        }
        return try {
            json.decodeFromString<List<NodeConfig>>(jsonStr)
        } catch (e: Exception) {
            Log.w(TAG, "Could not read the saved endpoints: ${e.message}")
            emptyList()
        }
    }

    /** Saves the relay configuration. */
    fun saveRelayConfig(relayMode: String, relayUrl: String, authToken: String) {
        prefs.edit()
            .putString(KEY_RELAY_MODE, relayMode)
            .putString(KEY_RELAY_URL, relayUrl)
            .putString(KEY_RELAY_AUTH_TOKEN, authToken)
            .apply()
    }

    /** Loads the relay mode; defaults to "pinned" (pinned to aps1-1). */
    fun loadRelayMode(): String {
        return prefs.getString(KEY_RELAY_MODE, "pinned") ?: "pinned"
    }

    /** Loads the custom relay URL. */
    fun loadRelayUrl(): String {
        return prefs.getString(KEY_RELAY_URL, "") ?: ""
    }

    /** Loads the bearer token for the custom relay, if it needs one. */
    fun loadRelayAuthToken(): String {
        return prefs.getString(KEY_RELAY_AUTH_TOKEN, "") ?: ""
    }
}
