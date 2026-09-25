package com.nexa.pipe.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

/**
 * One corner-radius scale for the whole app.
 *
 * Every button, card and dialog that used to hard-code a radius
 * (`RoundedCornerShape(8.dp)`, `50`, `24.dp`) now takes it from here, so a
 * screen cannot end up with three different-looking buttons on it. `medium` is
 * the default for buttons; cards use `large`.
 */
val NexaShapes = Shapes(
    extraSmall = RoundedCornerShape(4.dp),
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(12.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(28.dp),
)
