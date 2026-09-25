package com.nexa.pipe.locale

import android.content.Context
import androidx.annotation.StringRes
import com.nexa.pipe.SettingsManager

/**
 * Localized strings for the code that carries no [Context] of its own.
 *
 * The ViewModel builds most of its error messages deep inside private helpers,
 * far away from the Activity it was created with, and passing a Context down
 * to every one of them would be worse than this one indirection. It keeps the
 * *application* context, so nothing is leaked.
 *
 * The context is re-wrapped whenever the saved language changes: the Activity
 * and the VPN service wrap their own context in [AppLocale.apply], so the
 * process-wide default cannot be used as-is — it would still be in the device
 * language.
 */
object AppStrings {
    @Volatile private var application: Context? = null
    @Volatile private var localized: Context? = null
    @Volatile private var localizedTag: String? = null

    /** Called once, from `NexaApplication.onCreate`. */
    fun init(context: Context) {
        application = context.applicationContext
        localized = null
        localizedTag = null
    }

    /** [getString] in the selected language; empty before [init] has run. */
    fun get(@StringRes id: Int, vararg args: Any?): String {
        val base = application ?: return ""
        return contextFor(base).getString(id, *args)
    }

    private fun contextFor(base: Context): Context {
        val tag = SettingsManager.loadLanguage(base)
        val cached = localized
        if (cached != null && localizedTag == tag) return cached
        // Two threads may build one here; both are equivalent, and only one wins.
        val wrapped = AppLocale.wrap(base, tag)
        localizedTag = tag
        localized = wrapped
        return wrapped
    }
}
