package com.nexa.pipe.ui

import android.app.Activity
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R
import com.nexa.pipe.locale.AppLanguage
import com.nexa.pipe.locale.AppLocale
import com.nexa.pipe.locale.label
import com.nexa.pipe.ui.components.NexaTextButton

// ---------------------------------------------------------------------------
// Configurations > Language
//
// The picker is where the switch is: the language is a setting of this app,
// not of a session, so it belongs next to the endpoints rather than behind a
// menu item. Picking one rebuilds the Activity (see `applyLanguage`).
// ---------------------------------------------------------------------------

/**
 * The language the UI is in, and the way to change it.
 *
 * The current one is re-read on every composition instead of being remembered:
 * the row is only drawn while the settings panel is expanded, and a change
 * comes back as a new Activity anyway.
 */
@Composable
internal fun LanguageSection(
    onLanguagePicked: (AppLanguage) -> Unit
) {
    val context = LocalContext.current
    var showPicker by remember { mutableStateOf(false) }
    val current = AppLocale.selected(context)

    // No leading icon: `material-icons-core` (all the app can use with R8 off)
    // has no glyph for "language", and a wrong one is worse than none. The row
    // matches the endpoints section above it — title, subtitle, chevron.
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { showPicker = true },
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = stringResource(R.string.language_title),
                style = MaterialTheme.typography.titleSmall
            )
            Text(
                text = current.label(),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Icon(
            Icons.Default.KeyboardArrowRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }

    if (showPicker) {
        AlertDialog(
            onDismissRequest = { showPicker = false },
            title = { Text(stringResource(R.string.language_title)) },
            text = {
                Column {
                    AppLanguage.all().forEach { language ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    showPicker = false
                                    if (language != current) onLanguagePicked(language)
                                }
                                .padding(vertical = 2.dp)
                        ) {
                            RadioButton(
                                selected = language == current,
                                onClick = {
                                    showPicker = false
                                    if (language != current) onLanguagePicked(language)
                                }
                            )
                            Spacer(modifier = Modifier.width(8.dp))
                            Text(language.label(), style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            },
            confirmButton = {
                NexaTextButton(
                    text = stringResource(R.string.action_close),
                    onClick = { showPicker = false }
                )
            }
        )
    }
}
