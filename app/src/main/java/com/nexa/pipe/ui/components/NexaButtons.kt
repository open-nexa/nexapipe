package com.nexa.pipe.ui.components

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.nexa.pipe.ui.theme.Dimens

/**
 * The buttons every screen uses, so no screen invents its own.
 *
 * Before this, each call site chose its own radius (`8.dp` here, `50` there),
 * its own height and its own icon size, and dialogs used a bare `TextButton`
 * for both "Import" and "Delete" — two actions that do not deserve the same
 * weight. The rules here are the whole design:
 *
 *   - one radius (`Dimens.RadiusButton`), one minimum height (48dp, the
 *     accessible touch target), one icon size;
 *   - `primary` for the one thing the screen is for, `tonal` for alternatives,
 *     `danger` for anything destructive, `text` for dismissing;
 *   - `loading` keeps the button's width instead of swapping in a differently
 *     sized control, so the row does not jump while a request is in flight.
 */
private val ButtonShape = RoundedCornerShape(Dimens.RadiusButton)
private val ButtonPadding = PaddingValues(horizontal = 20.dp, vertical = 12.dp)

@Composable
private fun RowScope.ButtonContent(
    text: String,
    icon: ImageVector?,
    loading: Boolean,
) {
    if (loading) {
        CircularProgressIndicator(
            modifier = Modifier.size(Dimens.IconButton),
            strokeWidth = 2.dp,
        )
        Spacer(modifier = Modifier.width(Dimens.Space2))
    } else if (icon != null) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            modifier = Modifier.size(Dimens.IconButton),
        )
        Spacer(modifier = Modifier.width(Dimens.Space2))
    }
    Text(text = text, maxLines = 1)
}

@Composable
fun NexaPrimaryButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    loading: Boolean = false,
) {
    Button(
        onClick = onClick,
        modifier = modifier.heightIn(min = Dimens.MinTouchTarget),
        enabled = enabled && !loading,
        shape = ButtonShape,
        contentPadding = ButtonPadding,
    ) {
        ButtonContent(text = text, icon = icon, loading = loading)
    }
}

@Composable
fun NexaTonalButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    loading: Boolean = false,
) {
    FilledTonalButton(
        onClick = onClick,
        modifier = modifier.heightIn(min = Dimens.MinTouchTarget),
        enabled = enabled && !loading,
        shape = ButtonShape,
        contentPadding = ButtonPadding,
    ) {
        ButtonContent(text = text, icon = icon, loading = loading)
    }
}

/** Destructive: removal, disconnection. Never the same weight as a confirm. */
@Composable
fun NexaDangerButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    icon: ImageVector? = null,
    enabled: Boolean = true,
    loading: Boolean = false,
) {
    Button(
        onClick = onClick,
        modifier = modifier.heightIn(min = Dimens.MinTouchTarget),
        enabled = enabled && !loading,
        shape = ButtonShape,
        contentPadding = ButtonPadding,
        colors = ButtonDefaults.buttonColors(
            containerColor = MaterialTheme.colorScheme.error,
            contentColor = MaterialTheme.colorScheme.onError,
        ),
    ) {
        ButtonContent(text = text, icon = icon, loading = loading)
    }
}

/** Dismissive: "Cancel", "Not now". Keeps a 48dp target even though it has no background. */
@Composable
fun NexaTextButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    TextButton(
        onClick = onClick,
        modifier = modifier.heightIn(min = Dimens.MinTouchTarget),
        enabled = enabled,
        shape = ButtonShape,
        contentPadding = ButtonPadding,
    ) {
        Text(text = text, maxLines = 1)
    }
}
