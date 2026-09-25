package com.nexa.pipe.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

/**
 * Both schemes spell out the surface containers the screens read
 * (`surfaceContainerLow` for cards, `surfaceContainerHigh` for rows on them), so
 * a card is visibly a card in either theme instead of falling back to whatever
 * Material picked.
 */
private val DarkColorScheme = darkColorScheme(
    primary = NexaBlue300,
    onPrimary = NexaBlue800,
    primaryContainer = NexaBlue800,
    onPrimaryContainer = NexaBlue100,
    secondary = NexaSlate400,
    onSecondary = NexaSlate900,
    secondaryContainer = NexaSlate800,
    onSecondaryContainer = NexaSlate100,
    background = NexaSlate900,
    onBackground = NexaSlate50,
    surface = NexaSlate800,
    onSurface = NexaSlate50,
    surfaceVariant = NexaSlate800,
    onSurfaceVariant = NexaSlate200,
    surfaceContainerLowest = NexaSlate900,
    surfaceContainerLow = NexaSlate800,
    surfaceContainer = NexaSlate800,
    surfaceContainerHigh = NexaSlate800,
    surfaceContainerHighest = NexaSlate600,
    outline = NexaSlate600,
    error = NexaRed500,
    onError = NexaSlate900,
    errorContainer = NexaRed800,
    onErrorContainer = NexaRed100,
)

private val LightColorScheme = lightColorScheme(
    primary = NexaBlue600,
    onPrimary = NexaSlate50,
    primaryContainer = NexaBlue100,
    onPrimaryContainer = NexaBlue800,
    secondary = NexaSlate600,
    onSecondary = NexaSlate50,
    secondaryContainer = NexaSlate100,
    onSecondaryContainer = NexaSlate800,
    background = NexaSlate50,
    onBackground = NexaSlate900,
    surface = NexaSlate50,
    onSurface = NexaSlate900,
    surfaceVariant = NexaSlate100,
    onSurfaceVariant = NexaSlate600,
    surfaceContainerLowest = NexaSlate50,
    surfaceContainerLow = NexaSlate50,
    surfaceContainer = NexaSlate100,
    surfaceContainerHigh = NexaSlate100,
    surfaceContainerHighest = NexaSlate200,
    outline = NexaSlate400,
    error = NexaRed600,
    onError = NexaSlate50,
    errorContainer = NexaRed100,
    onErrorContainer = NexaRed800,
)

/**
 * The app theme.
 *
 * `dynamicColor` is off by default now. Material You takes the whole scheme
 * from the wallpaper, which meant the app changed colour every time the user
 * changed their background — and on anything below Android 12 it fell back to
 * the template purple, so two phones running the same build looked unrelated.
 * The brand scheme is the same everywhere instead; the parameter is left so it
 * can be offered as a setting later.
 */
@Composable
fun NexaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }

        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        shapes = NexaShapes,
        typography = Typography,
        content = content
    )
}
