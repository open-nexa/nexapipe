package com.nexa.pipe.auth

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The door in front of the credentials this app holds.
 *
 * `SecretStore` already seals them at rest under a keystore key, so the gap
 * this closes is the other half of R14: nothing asked anything before handing
 * them back, and the endpoint detail screen rendered a TOTP secret in full.
 * The vault existed; this is the door.
 *
 * Authentication is delegated to the operating system and to nothing else.
 * There is deliberately no app password — a credential of its own would be one
 * more thing to forget, reset and attack — so what gates the surfaces is the
 * same thing that gates the device: a biometric where one can be used, and the
 * screen-lock credential otherwise.
 *
 * Two rules shape the rest of the code:
 *
 * - **A device with nothing to authenticate against is refused, not
 *   downgraded.** Showing the secret because the device cannot ask is the
 *   one outcome this class exists to prevent.
 * - **The unlock is a window, not a mode.** It lives in memory for
 *   [UNLOCK_WINDOW_MS] and dies with the process; it is never persisted and
 *   never handed to the VPN service, which must keep being able to reopen its
 *   endpoints after a reboot with nobody present.
 */
object CredentialGate {

    /**
     * How long one successful authentication keeps the credential surfaces
     * open. Short enough that a phone set down does not stay unlocked, long
     * enough that reading one secret does not mean authenticating twice.
     */
    const val UNLOCK_WINDOW_MS = 2 * 60 * 1000L

    /** Whether this device can authenticate the user at all. */
    enum class Capability {
        /** A biometric or a screen-lock credential is enrolled. */
        Available,

        /**
         * Neither. Every surface stays shut: there is nothing to ask, and
         * "cannot ask" is not permission.
         */
        Unavailable,
    }

    /**
     * What the device has to authenticate with.
     *
     * `isDeviceSecure` rather than a biometric-specific check: it is what
     * `KeyguardManager` needs on API 26-29, and on API 30+ the screen-lock
     * credential is exactly the fallback `BiometricPrompt` offers when the
     * sensor cannot be used. A device with a fingerprint but no PIN is not
     * secure in the sense that matters here.
     */
    fun capability(context: Context): Capability {
        val manager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            ?: return Capability.Unavailable
        return if (manager.isDeviceSecure) Capability.Available else Capability.Unavailable
    }

    /**
     * Whether the window that ends at [untilMs] is still open.
     *
     * Split out from [isUnlocked] so the rule is testable without a clock, a
     * device or a `Context`.
     */
    fun isUnlockedAt(nowMs: Long, untilMs: Long): Boolean = untilMs > nowMs

    /**
     * When the current window ends, on [SystemClock.elapsedRealtime].
     *
     * Elapsed time rather than wall-clock: a window measured against the wall
     * clock can be closed or reopened by the user changing the time, and an
     * unlock is not something the clock should have a say in.
     */
    private val windowEndsAt = MutableStateFlow(0L)

    /** Read by the UI, which recomposes both on unlock and on expiry. */
    val windowEndsAtElapsed: StateFlow<Long> get() = windowEndsAt

    fun isUnlocked(nowMs: Long = SystemClock.elapsedRealtime()): Boolean =
        isUnlockedAt(nowMs, windowEndsAt.value)

    /** Opens the window for [UNLOCK_WINDOW_MS] from now. */
    fun unlock(nowMs: Long = SystemClock.elapsedRealtime()) {
        windowEndsAt.value = nowMs + UNLOCK_WINDOW_MS
    }

    /**
     * Closes it again. Called when the window lapses, and when the device turns
     * out to have lost the ability to ask — see [refreshCapability]. Nothing
     * else closes it: this is not a setting, and there is no way to ask for the
     * surfaces to stay open.
     */
    fun lock() {
        windowEndsAt.value = 0L
    }

    /**
     * Closes the window if the device can no longer ask who is using it.
     *
     * Called when the app returns to the foreground. The window is two minutes
     * of memory and nothing re-checks it while it runs, so a screen lock
     * removed while this app was in the background leaves it open on a device
     * that cannot confirm anybody — which is the outcome [Capability.Unavailable]
     * exists to prevent. Coming back into view is the one moment worth asking
     * again, and it costs nothing: either the device can still ask, and the
     * window it already had stands, or it cannot, and nothing should be open.
     */
    fun refreshCapability(context: Context) {
        if (capability(context) != Capability.Available) {
            lock()
        }
    }

    /**
     * Whether API 30+ is where the prompt belongs.
     *
     * Below 30 `BiometricPrompt` is fingerprint-only, and Google documents
     * `DEVICE_CREDENTIAL` — alone or combined with a biometric — as
     * unsupported there, so a device with a PIN and no sensor would have
     * nothing to fall back on. Those versions go through [confirmCredentialIntent].
     */
    fun usesBiometricPrompt(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

    /**
     * Shows the system authentication prompt, on API 30 and above.
     *
     * Both `BIOMETRIC_STRONG` and `DEVICE_CREDENTIAL` are allowed so that a
     * device with no sensor, or one whose sensor is unavailable, can still get
     * in with its screen lock. That combination forbids a negative button,
     * which is why none is set: the way out of this prompt is to dismiss it.
     */
    fun authenticateWithBiometricPrompt(
        activity: FragmentActivity,
        title: CharSequence,
        subtitle: CharSequence?,
        onUnlocked: () -> Unit,
        onUnavailable: () -> Unit,
        onError: (CharSequence) -> Unit,
    ) {
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                unlock()
                onUnlocked()
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                when (errorCode) {
                    // Nothing on this device can authenticate, so there is
                    // nothing to retry: say so instead of reporting a failure
                    // the user cannot act on.
                    BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
                    BiometricPrompt.ERROR_NO_BIOMETRICS,
                    BiometricPrompt.ERROR_HW_NOT_PRESENT -> onUnavailable()

                    // Backing out is not a failure, and not worth a message.
                    BiometricPrompt.ERROR_USER_CANCELED,
                    BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                    BiometricPrompt.ERROR_CANCELED -> Unit

                    else -> onError(errString)
                }
            }

            /**
             * Not an error: an unrecognised finger or face. The prompt stays up
             * and keeps trying, so there is nothing to report and no reason to
             * close the surface.
             */
            override fun onAuthenticationFailed() = Unit
        }

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .apply { if (!subtitle.isNullOrEmpty()) setSubtitle(subtitle) }
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()

        BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            .authenticate(info)
    }

    /**
     * The intent that asks for the screen-lock credential, for API 26 to 29.
     *
     * Null when the device has none to give, which is [Capability.Unavailable]
     * by another route: the caller must treat that as a refusal.
     */
    fun confirmCredentialIntent(
        context: Context,
        title: CharSequence,
        description: CharSequence?,
    ): Intent? {
        val manager = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            ?: return null
        // Deprecated in favour of BiometricPrompt from API 30, which is exactly
        // the version [usesBiometricPrompt] switches to. On 26-29 it is the
        // only way to ask for a device credential, and it is not going away
        // underneath a device that is already running it.
        @Suppress("DEPRECATION")
        return manager.createConfirmDeviceCredentialIntent(title, description)
    }
}
