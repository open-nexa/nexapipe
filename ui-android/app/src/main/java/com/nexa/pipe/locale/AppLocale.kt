package com.nexa.pipe.locale

import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import com.nexa.pipe.R
import com.nexa.pipe.SettingsManager
import java.util.Locale

/**
 * A language the UI can be shown in.
 *
 * [SYSTEM] is not a language of its own: it leaves the context alone, so the
 * device language applies — including the per-app language Android 13+ lets
 * the user set from the system settings.
 */
enum class AppLanguage(val tag: String) {
    SYSTEM(""),
    ENGLISH("en"),
    SIMPLIFIED_CHINESE("zh-CN");

    companion object {
        /** Everything the picker offers, in the order it is shown. */
        fun all(): List<AppLanguage> = values().toList()

        /** The language [tag] names, or [SYSTEM] when it names none. */
        fun of(tag: String): AppLanguage = values().firstOrNull { it.tag == tag } ?: SYSTEM
    }
}

/**
 * The name of a language as it is shown in the picker: in that language, so
 * it stays readable when the app itself is in another one.
 */
@Composable
fun AppLanguage.label(): String = when (this) {
    AppLanguage.SYSTEM -> stringResource(R.string.language_system)
    AppLanguage.ENGLISH -> stringResource(R.string.language_english)
    AppLanguage.SIMPLIFIED_CHINESE -> stringResource(R.string.language_chinese_simplified)
}

/**
 * Applies the selected language to a context.
 *
 * Android resolves resources per context, not per process, so every component
 * that shows text has to wrap *its own* context in [apply] — the Activity and
 * the VPN service do it in `attachBaseContext`. Wrapping the application
 * context alone would leave both of them in the device language.
 */
object AppLocale {
    /** The language picked in the settings. */
    fun selected(context: Context): AppLanguage = AppLanguage.of(SettingsManager.loadLanguage(context))

    /**
     * Persists [language]. Nothing on screen changes by itself: the caller has
     * to recreate the Activity so it is rebuilt through [apply].
     */
    fun select(context: Context, language: AppLanguage) =
        SettingsManager.saveLanguage(context, language.tag)

    /** A [context] whose resources are in the language saved in the settings. */
    fun apply(context: Context): Context = wrap(context, SettingsManager.loadLanguage(context))

    /**
     * A [context] whose resources are in [tag]; the context itself when [tag]
     * is empty, i.e. "follow the system".
     */
    fun wrap(context: Context, tag: String): Context {
        if (tag.isBlank()) return context
        val config = Configuration(context.resources.configuration)
        config.setLocales(LocaleList(Locale.forLanguageTag(tag)))
        return context.createConfigurationContext(config)
    }
}
