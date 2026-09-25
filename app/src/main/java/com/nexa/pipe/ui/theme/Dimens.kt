package com.nexa.pipe.ui.theme

import androidx.compose.ui.unit.dp

/**
 * Spacing, radius and touch-target constants.
 *
 * Kept as one object rather than scattered literals so a screen cannot drift by
 * 2dp per card. `MinTouchTarget` is the one that matters for accessibility: a
 * 32dp icon button is easy to miss, and the collapsible card headers used to be
 * exactly that.
 */
object Dimens {
    val Space1 = 4.dp
    val Space2 = 8.dp
    val Space3 = 12.dp
    val Space4 = 16.dp
    val Space5 = 20.dp
    val Space6 = 24.dp

    /** Minimum size of anything tappable. */
    val MinTouchTarget = 48.dp

    val RadiusButton = 12.dp
    val RadiusCard = 16.dp
    val RadiusChip = 8.dp

    /** Icons inside buttons: large enough to read, small enough not to dominate the label. */
    val IconButton = 18.dp
    val IconSmall = 16.dp
}
