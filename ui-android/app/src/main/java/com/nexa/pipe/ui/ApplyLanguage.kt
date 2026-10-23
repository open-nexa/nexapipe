package com.nexa.pipe.ui

import android.app.Activity
import android.content.Context
import com.nexa.pipe.locale.AppLanguage
import com.nexa.pipe.locale.AppLocale

/**
 * Switches the UI to [language] and rebuilds the Activity.
 *
 * The rebuild is not a shortcut: resources are resolved per context, so the
 * only way every string on screen changes is going through
 * `MainActivity.attachBaseContext` again. `recreate()` keeps the
 * ViewModel (and with it the running session's state) alive, so the UI
 * comes back where it was — only in the new language.
 */
internal fun applyLanguage(context: Context, language: AppLanguage) {
    AppLocale.select(context, language)
    (context as? Activity)?.recreate()
}
