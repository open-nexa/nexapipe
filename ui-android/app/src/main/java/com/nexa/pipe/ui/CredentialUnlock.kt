package com.nexa.pipe.ui

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.os.SystemClock
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.nexa.pipe.R
import com.nexa.pipe.auth.CredentialGate
import kotlinx.coroutines.delay

/**
 * The state of the credential door, as a screen sees it.
 *
 * A snapshot rather than a handle with behaviour of its own: it is rebuilt on
 * every recomposition from state that lives in the composition, so a screen
 * calling [request] always gets the current window and the current context,
 * never a stale one captured when the page was first drawn.
 */
class CredentialUnlock internal constructor(
    /** Whether credentials may be shown right now. */
    val unlocked: Boolean,

    /** Whether the last request was refused because the device cannot ask. */
    val unavailable: Boolean,

    private val onRequest: (title: CharSequence, subtitle: CharSequence?, onUnlocked: () -> Unit) -> Unit,
    private val onDismissUnavailable: () -> Unit,
) {
    /**
     * Asks the operating system to confirm the user, then runs [action].
     *
     * [action] rather than a second tap: authentication is the thing that
     * stands in front of the disclosure, not a step of its own, so what the
     * user asked for happens as soon as the system says yes. Nothing runs if
     * the system says no, and nothing runs if the device cannot be asked.
     */
    fun request(title: CharSequence, subtitle: CharSequence? = null, action: () -> Unit = { }) =
        onRequest(title, subtitle, action)

    /**
     * Runs [action] now when the door is already open, and asks for it first
     * when it is not.
     *
     * One authentication covers every surface for [CredentialGate.UNLOCK_WINDOW_MS],
     * so re-asking inside that window would only be friction: the device has
     * already said who is using it, and a second confirmation says nothing the
     * first one did not.
     */
    fun requestIfLocked(
        title: CharSequence,
        subtitle: CharSequence? = null,
        action: () -> Unit,
    ) {
        if (unlocked) action() else request(title, subtitle, action)
    }

    /** Closes the "this device cannot ask" dialog. */
    fun dismissUnavailable() = onDismissUnavailable()
}

/**
 * [CredentialUnlock.requestIfLocked] for the common case.
 *
 * The title is the same on every surface, so only the subtitle — the one line
 * that says what is about to be allowed — differs; [context] is the
 * locale-wrapped one, so the prompt is in the language the screen is in.
 */
fun CredentialUnlock.requestIfLocked(
    context: Context,
    subtitleRes: Int,
    action: () -> Unit,
) = requestIfLocked(
    context.getString(R.string.credential_lock_title),
    context.getString(subtitleRes),
    action
)

/**
 * Wires the credential door into a screen.
 *
 * It owns the one thing that cannot live in [CredentialGate]: the activity
 * result launcher for the API 26-29 credential screen, which has to be
 * registered in composition. Everything else — the window, the capability
 * check, the prompt — is the gate's.
 */
@Composable
fun rememberCredentialUnlock(): CredentialUnlock {
    val context = LocalContext.current
    val activity = remember(context) { context.findFragmentActivity() }

    var unavailable by remember { mutableStateOf(false) }

    // What the user asked for before being asked to confirm. Held rather than
    // run early: an authentication that is refused, or a device that cannot
    // authenticate at all, must leave it undone.
    var pendingAction by remember { mutableStateOf<(() -> Unit)?>(null) }

    fun refuse() {
        pendingAction = null
        unavailable = true
    }

    fun runConfirmed() {
        val action = pendingAction
        pendingAction = null
        CredentialGate.unlock()
        action?.invoke()
    }

    val confirmCredential = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        // RESULT_OK is the only answer that means anything here: the confirm
        // screen either confirms or goes away, and going away is a no.
        if (result.resultCode == Activity.RESULT_OK) {
            runConfirmed()
        }
    }

    val windowEndsAt by CredentialGate.windowEndsAtElapsed.collectAsState()
    var unlocked by remember { mutableStateOf(CredentialGate.isUnlocked()) }

    // The window is time, not a flag, so something has to close it when it
    // lapses. This is that something: it restarts whenever the window moves,
    // and is cancelled when the screen leaves the composition.
    LaunchedEffect(windowEndsAt) {
        val remaining = windowEndsAt - SystemClock.elapsedRealtime()
        if (remaining <= 0L) {
            unlocked = false
            return@LaunchedEffect
        }
        unlocked = true
        delay(remaining)
        unlocked = false
    }

    // The window is memory, and nothing re-checks what the device can do while
    // it runs: a screen lock removed while this app was in the background would
    // leave the surfaces open on a device that cannot confirm anybody. Coming
    // back into view is the one moment worth asking again — a device that can
    // still ask keeps the window it already had.
    val lifecycleOwner = LocalLifecycleOwner.current
    DisposableEffect(lifecycleOwner) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == androidx.lifecycle.Lifecycle.Event.ON_RESUME) {
                CredentialGate.refreshCapability(context)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }

    return CredentialUnlock(
        unlocked = unlocked,
        unavailable = unavailable,
        onRequest = { title, subtitle, action ->
            if (CredentialGate.capability(context) != CredentialGate.Capability.Available) {
                refuse()
            } else {
                pendingAction = action
                when {
                    CredentialGate.usesBiometricPrompt() && activity != null ->
                        CredentialGate.authenticateWithBiometricPrompt(
                            activity,
                            title,
                            subtitle,
                            onUnlocked = ::runConfirmed,
                            onUnavailable = ::refuse,
                            onError = { message ->
                                // A lockout or a vendor failure, in the system's
                                // own words: translating it would only
                                // paraphrase it.
                                pendingAction = null
                                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
                            },
                        )

                    else -> {
                        val intent = CredentialGate.confirmCredentialIntent(context, title, subtitle)
                        if (intent == null) refuse() else confirmCredential.launch(intent)
                    }
                }
            }
        },
        onDismissUnavailable = { unavailable = false },
    )
}

/**
 * Shown when the device has no way to confirm the user.
 *
 * A dialog rather than a toast because refusing is only half the job: the
 * credential is unreachable until the device can ask, and the way out of that
 * is a screen lock, which is one tap from here.
 */
@Composable
fun CredentialUnavailableDialog(unlock: CredentialUnlock) {
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = unlock::dismissUnavailable,
        title = { Text(stringResource(R.string.credential_lock_unavailable_title)) },
        text = { Text(stringResource(R.string.credential_lock_unavailable_body)) },
        confirmButton = {
            TextButton(
                onClick = {
                    context.startActivity(Intent(Settings.ACTION_SECURITY_SETTINGS))
                    unlock.dismissUnavailable()
                }
            ) {
                Text(stringResource(R.string.credential_lock_unavailable_action))
            }
        },
        dismissButton = {
            TextButton(onClick = unlock::dismissUnavailable) {
                Text(stringResource(R.string.action_close))
            }
        }
    )
}

/**
 * The FragmentActivity hosting this composition, or null.
 *
 * `BiometricPrompt` will not host itself in anything else, so the activity is
 * looked up rather than assumed: a Preview, or a composable reached from the
 * VPN service's own context, has no FragmentActivity behind it, and a cast that
 * threw there would take the screen down.
 */
private fun Context.findFragmentActivity(): FragmentActivity? {
    var current: Context? = this
    while (current is ContextWrapper) {
        if (current is FragmentActivity) return current
        current = current.baseContext
    }
    return null
}
