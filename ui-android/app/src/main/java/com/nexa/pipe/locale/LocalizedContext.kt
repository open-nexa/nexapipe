package com.nexa.pipe.locale

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext

/**
 * A context whose resources follow the configuration of the composition it was
 * read in, for the code that needs a resource value outside a composable
 * scope: a click handler, a coroutine, a camera callback.
 *
 * Those places cannot call `stringResource`, and reading `LocalContext.current`
 * instead is what the lint check `LocalContextGetResourceValueCall` flags: the
 * value it answers with outlives the configuration it was taken from, so a
 * language or a theme change can leave that code holding a stale string.
 * Binding the context to `LocalConfiguration` — which *is* read in the
 * composition — puts the value back into it: a new configuration means a new
 * context, and the handlers captured afterwards see the new one.
 *
 * Use it for resource lookups only. The APIs that want a real context — Toast,
 * permissions, the ViewModel — keep taking `LocalContext.current`.
 */
@Composable
fun rememberLocalizedContext(): Context {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    return remember(context, configuration) { context.createConfigurationContext(configuration) }
}
