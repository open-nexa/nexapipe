package com.nexa.pipe.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.nexa.pipe.R

/**
 * How traffic to a backend is actually routed, as reported by iroh at runtime.
 *
 * Deliberately not derived from the configured relay URL: that only names a relay that *may*
 * be used, while this says whether the hole punch succeeded.
 */
enum class LinkKind {
    /** A direct UDP path to the backend is carrying the traffic. */
    DIRECT,

    /** Traffic goes through a relay server. */
    RELAY,

    /** Connected, but no path has been selected yet. */
    UNKNOWN,
}

/** Short label for the icon; also its talk-back description. */
@Composable
fun linkKindLabel(kind: LinkKind): String = when (kind) {
    LinkKind.DIRECT -> stringResource(R.string.link_direct)
    LinkKind.RELAY -> stringResource(R.string.link_relay)
    LinkKind.UNKNOWN -> stringResource(R.string.link_connecting)
}

/** Direct is the good case, relay still works but is a detour, and undetermined is muted. */
@Composable
private fun linkKindTint(kind: LinkKind): Color = when (kind) {
    LinkKind.DIRECT -> MaterialTheme.colorScheme.primary
    LinkKind.RELAY -> MaterialTheme.colorScheme.tertiary
    LinkKind.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
}

/**
 * The link type of [nodeId] in the map the ViewModel publishes, or null when it says nothing
 * about that backend.
 *
 * Callers must read this from a *collected* map, not from `StateFlow.value`, or the UI will
 * never recompose when the link changes. The case-insensitive fallback costs nothing at this
 * size and covers an endpoint ID that came back in a different case than the one configured.
 */
fun linkKindOf(kinds: Map<String, LinkKind>, nodeId: String): LinkKind? =
    kinds[nodeId]
        ?: kinds.entries.firstOrNull { it.key.equals(nodeId, ignoreCase = true) }?.value

/**
 * The icon with its name beside it.
 *
 * The glyph alone is easy to misread at a glance — "one hop" and "two hops with something in
 * between" are close cousins — so wherever there is room the label travels with it. The chip
 * also carries the talk-back description, so the pair is announced once, not twice.
 */
@Composable
fun LinkKindBadge(
    kind: LinkKind,
    modifier: Modifier = Modifier,
) {
    val tint = linkKindTint(kind)
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(50),
        color = tint.copy(alpha = 0.12f),
        contentColor = tint,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            // The icon's own description is dropped: the label next to it says the same thing,
            // and hearing "Direct, Direct" is worse than hearing it once.
            LinkKindIcon(kind, iconSize = 14.dp, modifier = Modifier.clearAndSetSemantics { })
            Spacer(modifier = Modifier.width(5.dp))
            Text(
                text = linkKindLabel(kind),
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Medium,
                maxLines = 1,
            )
        }
    }
}

/**
 * Two peers and the link between them.
 *
 * Drawn instead of taken from the icon set so the states read as one picture: a direct link
 * is a single hop, a relayed one goes through a hollow third node in the middle, and an
 * undetermined one is a dashed line. The extra node *is* the difference, which no generic
 * "globe" or "arrow" icon conveys.
 */
@Composable
fun LinkKindIcon(
    kind: LinkKind,
    modifier: Modifier = Modifier,
    iconSize: Dp = 16.dp,
    tint: Color = linkKindTint(kind),
) {
    val label = linkKindLabel(kind)
    Canvas(
        modifier = modifier
            .semantics { contentDescription = label }
            .size(iconSize)
    ) {
        // `size` here is DrawScope.size — hence `iconSize` for the parameter.
        val w = size.width
        val cy = size.height / 2f
        val dotRadius = w * 0.15f
        val lineWidth = w * 0.09f
        val leftX = dotRadius * 1.6f
        val rightX = w - dotRadius * 1.6f
        val cap = StrokeCap.Round
        // A dashed line says "not settled yet" without inventing a third glyph.
        val dash = if (kind == LinkKind.UNKNOWN) {
            PathEffect.dashPathEffect(floatArrayOf(w * 0.12f, w * 0.1f))
        } else {
            null
        }

        if (kind == LinkKind.RELAY) {
            drawLine(
                tint,
                Offset(leftX, cy),
                Offset(w / 2f, cy),
                strokeWidth = lineWidth,
                cap = cap,
                pathEffect = dash,
            )
            drawLine(
                tint,
                Offset(w / 2f, cy),
                Offset(rightX, cy),
                strokeWidth = lineWidth,
                cap = cap,
                pathEffect = dash,
            )
            // Hollow: an intermediary hop, not one of the two ends.
            drawCircle(
                tint,
                radius = dotRadius * 0.8f,
                center = Offset(w / 2f, cy),
                style = Stroke(width = lineWidth * 0.9f),
            )
        } else {
            drawLine(
                tint,
                Offset(leftX, cy),
                Offset(rightX, cy),
                strokeWidth = lineWidth,
                cap = cap,
                pathEffect = dash,
            )
        }

        drawCircle(tint, radius = dotRadius, center = Offset(leftX, cy))
        drawCircle(tint, radius = dotRadius, center = Offset(rightX, cy))
    }
}
