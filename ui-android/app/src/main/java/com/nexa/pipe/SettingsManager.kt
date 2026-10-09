package com.nexa.pipe

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import androidx.core.content.edit
import com.nexa.pipe.ui.NodeConfig
import com.nexa.pipe.ui.NodeTwoFactor
import com.nexa.pipe.vpn.VpnTakeoverChoice
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
    // Every credential written to `secretPrefs` goes through this, so the file
    // holds ciphertext even though it is a plain preferences file.
    private val secrets = SecretStore()

    init {
        migrateLegacyTwoFactor()
        migrateRelayAuthToken()
        migrateSecretsAtRest()
    }

    companion object {
        private const val TAG = "SettingsManager"
        const val PREFS_NAME = "NexaPipeSettings"
        const val KEY_NODES = "nodes"
        const val KEY_RELAY_MODE = "relay_mode"
        const val KEY_RELAY_URL = "relay_url"
        // The relay bearer token. Kept in `secretPrefs`, not `prefs`: the relay
        // is handed it verbatim, so it is a credential like the TOTP seeds, and
        // only the secrets file is excluded from cloud backup and device
        // transfer. Left in `prefs` it rode the very backup that is careful not
        // to take the seeds.
        const val KEY_RELAY_AUTH_TOKEN = "relay_auth_token"
        // Prefix of the per-endpoint secret entries in `secretPrefs`.
        const val SECRET_PREFIX = "two_factor_secret_"
        // Prefix of the per-endpoint enrollment tokens. A token is a credential
        // too — it is what a registration invite hands out — so it is kept out
        // of the backed-up list alongside the secrets.
        const val ENROLLMENT_PREFIX = "enrollment_token_"
        // Read once by `migrateLegacyTwoFactor` and then deleted: 2FA used to
        // be one app-wide setting, it now belongs to an endpoint.
        const val KEY_2FA_ENABLED = "two_factor_enabled"
        const val KEY_2FA_CLIENT_ID = "two_factor_client_id"
        const val KEY_2FA_SECRET = "two_factor_secret"
        const val KEY_2FA_ALGORITHM = "two_factor_algorithm"
        const val KEY_2FA_MIGRATED = "two_factor_migrated"

        /**
         * The name this install answers as when it authenticates.
         *
         * It lives in [secretPrefs] rather than the backed-up file: it names
         * *this* device, and a configuration restored onto another phone must
         * not turn up claiming to be the one it was copied from. Sealed like
         * the credentials beside it, because that file being ciphertext
         * throughout is the property its exclusion from backups rests on —
         * the name itself is not a secret.
         */
        const val KEY_DEVICE_ID = "device_id"

        // Language tag of the app UI, e.g. "zh-CN". Empty means "follow the
        // system", which is the default.
        private const val KEY_LANGUAGE = "app_language"

        // What the user chose the last time another VPN app owned the slot:
        // "take_over" or "cancel". Absent means "ask every time", which is the
        // default — a remembered choice is only written when one was made.
        private const val KEY_VPN_TAKEOVER_CHOICE = "vpn_takeover_choice"

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
     * Persists the endpoints. The 2FA secret — and any enrollment token — of
     * each endpoint is written to [secretPrefs] and stripped from the list
     * saved in [prefs], so the backed up copy carries the configuration but
     * never a credential.
     */
    fun saveNodes(nodes: List<NodeConfig>) {
        val editor = secretPrefs.edit()
        // A secret outlives its endpoint otherwise: deleting the endpoint
        // would leave the seed behind, and the next endpoint to reuse that ID
        // would inherit it.
        for (key in secretPrefs.all.keys) {
            if (key.startsWith(SECRET_PREFIX)) {
                val nodeId = key.removePrefix(SECRET_PREFIX)
                val otp = nodes.firstOrNull { it.nodeId == nodeId }?.twoFactor
                if (otp == null || otp.secret.isBlank()) {
                    editor.remove(key)
                }
            }
            if (key.startsWith(ENROLLMENT_PREFIX)) {
                val nodeId = key.removePrefix(ENROLLMENT_PREFIX)
                val enrollment = nodes.firstOrNull { it.nodeId == nodeId }?.enrollment
                if (enrollment == null || enrollment.token.isBlank()) {
                    editor.remove(key)
                }
            }
        }

        val persisted = nodes.map { node ->
            val stripped = node.enrollment?.let { enrollment ->
                if (enrollment.token.isBlank()) {
                    null
                } else {
                    editor.putString(ENROLLMENT_PREFIX + node.nodeId, secrets.seal(enrollment.token))
                    node.copy(enrollment = enrollment.copy(token = ""))
                }
            } ?: node
            val otp = stripped.twoFactor
            if (otp == null || otp.secret.isBlank()) {
                stripped
            } else {
                editor.putString(SECRET_PREFIX + node.nodeId, secrets.seal(otp.secret))
                stripped.copy(twoFactor = otp.copy(secret = ""))
            }
        }
        editor.apply()
        prefs.edit().putString(KEY_NODES, json.encodeToString(persisted)).apply()
    }

    /**
     * What became of the last credential written to [secretPrefs].
     *
     * [SecretStore.Protection.Sealed] is the only answer that means the file
     * holds ciphertext. The others mean a credential went down as plaintext,
     * which the file being excluded from backups does not make harmless — it
     * only stops it leaving the device. The UI asks, so the user can be told
     * instead of finding out from a backup they assumed was encrypted.
     */
    fun credentialProtection(): SecretStore.Protection = secrets.protection()

    /**
     * The name this install answers as, generated on first call and then kept.
     *
     * A server can revoke one device of a client — or rate-limit it — only if
     * that device answers with a name of its own, so every install gets one
     * whether or not anything was asked of it.
     *
     * Kept rather than regenerated, because a name that changed between runs
     * would leave the server holding a row for every device this phone has
     * ever claimed to be.
     */
    fun deviceId(): String {
        val saved = secrets.unseal(secretPrefs.getString(KEY_DEVICE_ID, "") ?: "")
        if (saved.isNotBlank()) return saved
        val generated = DeviceName.generate(Build.MODEL)
        secretPrefs.edit { putString(KEY_DEVICE_ID, secrets.seal(generated)) }
        return generated
    }

    /** Loads the endpoints, re-attaching each secret and token from [secretPrefs]. */
    fun loadNodes(): List<NodeConfig> {
        val stored = decodeNodes()
        if (stored.isEmpty()) return stored
        return stored.map { node ->
            val withToken = node.enrollment?.let { enrollment ->
                val token = secrets.unseal(secretPrefs.getString(ENROLLMENT_PREFIX + node.nodeId, ""))
                node.copy(enrollment = enrollment.copy(token = token))
            } ?: node
            val otp = withToken.twoFactor ?: return@map withToken
            val secret = secrets.unseal(secretPrefs.getString(SECRET_PREFIX + node.nodeId, ""))
            withToken.copy(twoFactor = otp.copy(secret = secret))
        }
    }

    /**
     * Moves a relay token that an older version wrote to [prefs] into
     * [secretPrefs].
     *
     * Runs on every start but only does anything once: the key is removed from
     * [prefs] whether or not the token is worth keeping, so a blank one — the
     * value saved whenever a relay needs no token — does not leave the file
     * marked as holding a credential.
     */
    private fun migrateRelayAuthToken() {
        if (!prefs.contains(KEY_RELAY_AUTH_TOKEN)) {
            return
        }
        val token = prefs.getString(KEY_RELAY_AUTH_TOKEN, "") ?: ""
        prefs.edit().remove(KEY_RELAY_AUTH_TOKEN).apply()
        if (token.isBlank()) {
            return
        }
        secretPrefs.edit { putString(KEY_RELAY_AUTH_TOKEN, secrets.seal(token)) }
        Log.i(TAG, "Moved the relay auth token out of the backed-up preferences")
    }

    /**
     * Encrypts the credentials older versions left in [secretPrefs] as
     * plaintext.
     *
     * Not required for correctness — [loadNodes] reads plaintext values too —
     * but it is what takes the plaintext off the disk, and without it a
     * credential nobody has edited since would stay readable forever.
     *
     * Each value is sealed and read back before it is written, so one that
     * cannot be opened keeps its plaintext instead of becoming an
     * undecryptable blob. A value that could not be sealed at all is left
     * alone, and this runs again on the next start.
     */
    private fun migrateSecretsAtRest() {
        val keys = secretPrefs.all.keys.toList()
        if (keys.isEmpty()) return
        val editor = secretPrefs.edit()
        var sealed = 0
        for (key in keys) {
            if (!isCredentialKey(key)) continue
            val plain = secretPrefs.getString(key, "") ?: ""
            if (plain.isEmpty() || plain.startsWith(SecretStore.MARKER)) continue
            val written = secrets.seal(plain)
            // `seal` hands the value back untouched when it has no key, so
            // this is both the "nothing was encrypted" and the "no key" case.
            if (written == plain) continue
            if (secrets.unseal(written) != plain) {
                Log.e(TAG, "Left $key in plaintext: the sealed value did not read back")
                continue
            }
            editor.putString(key, written)
            sealed++
        }
        if (sealed > 0) {
            editor.apply()
            Log.i(TAG, "Encrypted $sealed stored credential(s)")
        }
    }

    /**
     * Whether [key] names a credential in [secretPrefs].
     *
     * The file also holds non-credentials — the migration flag, for one — and
     * those must stay readable as they are.
     */
    private fun isCredentialKey(key: String): Boolean =
        key == KEY_RELAY_AUTH_TOKEN ||
            key.startsWith(SECRET_PREFIX) ||
            key.startsWith(ENROLLMENT_PREFIX)

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
        prefs.edit {
            putString(KEY_RELAY_MODE, relayMode)
            putString(KEY_RELAY_URL, relayUrl)
        }
        // The token is written to the secrets file, and dropped rather than
        // stored blank, for the reasons given at [KEY_RELAY_AUTH_TOKEN].
        if (authToken.isBlank()) {
            secretPrefs.edit { remove(KEY_RELAY_AUTH_TOKEN) }
        } else {
            secretPrefs.edit { putString(KEY_RELAY_AUTH_TOKEN, secrets.seal(authToken)) }
        }
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
        return secrets.unseal(secretPrefs.getString(KEY_RELAY_AUTH_TOKEN, ""))
    }

    /**
     * Stores what the user wants done when another VPN app owns the slot.
     *
     * [VpnTakeoverChoice.Ask] removes the key rather than writing "ask": the
     * default is a preference file that does not mention the choice at all, so
     * an app that cannot read a value back is back to asking rather than to a
     * remembered answer nobody remembers making.
     */
    fun saveVpnTakeoverChoice(choice: VpnTakeoverChoice) {
        if (choice == VpnTakeoverChoice.Ask) {
            prefs.edit { remove(KEY_VPN_TAKEOVER_CHOICE) }
        } else {
            prefs.edit { putString(KEY_VPN_TAKEOVER_CHOICE, choice.name) }
        }
    }

    /** Loads the remembered takeover choice; [VpnTakeoverChoice.Ask] by default. */
    fun loadVpnTakeoverChoice(): VpnTakeoverChoice {
        val stored = prefs.getString(KEY_VPN_TAKEOVER_CHOICE, null) ?: return VpnTakeoverChoice.Ask
        return runCatching { VpnTakeoverChoice.valueOf(stored) }
            .getOrDefault(VpnTakeoverChoice.Ask)
    }
}
