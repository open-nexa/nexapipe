package com.nexa.pipe.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.google.zxing.BarcodeFormat
import com.nexa.pipe.R
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** Side of the generated bitmap in pixels; scaled down by the layout. */
private const val QR_SIZE_PX = 720

/** Quiet zone in modules, matching the spec's recommendation and `qr.rs`. */
private const val QUIET_ZONE_MODULES = 4

/**
 * Renders [content] as a QR code.
 *
 * Modules are always drawn black on white regardless of the active theme: an
 * inverted code (light modules on a dark background) is unreadable for most
 * scanners, so the white card is part of the feature, not a style choice.
 */
@Composable
fun QrCodeImage(content: String, modifier: Modifier = Modifier) {
    val bitmap = remember(content) { runCatching { encodeQrCode(content) }.getOrNull() }

    Box(modifier = modifier, contentAlignment = Alignment.Center) {
        val image = bitmap
        if (image == null) {
            Text(
                text = stringResource(R.string.qr_code_render_failed),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error
            )
        } else {
            Surface(color = Color.White, shape = RoundedCornerShape(12.dp)) {
                Image(
                    bitmap = image,
                    contentDescription = stringResource(R.string.qr_code_cd),
                    contentScale = ContentScale.Fit,
                    modifier = Modifier
                        .padding(12.dp)
                        .fillMaxWidth()
                        .aspectRatio(1f)
                )
            }
        }
    }
}

private fun encodeQrCode(content: String): ImageBitmap {
    val hints = mapOf(
        EncodeHintType.CHARACTER_SET to "UTF-8",
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
        // The full spec quiet zone is baked into the bitmap; the surrounding
        // white Surface stays as purely visual breathing room.
        EncodeHintType.MARGIN to QUIET_ZONE_MODULES
    )
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, QR_SIZE_PX, QR_SIZE_PX, hints)
    val pixels = IntArray(QR_SIZE_PX * QR_SIZE_PX)
    for (y in 0 until QR_SIZE_PX) {
        val rowStart = y * QR_SIZE_PX
        for (x in 0 until QR_SIZE_PX) {
            pixels[rowStart + x] = if (matrix.get(x, y)) android.graphics.Color.BLACK else android.graphics.Color.WHITE
        }
    }
    return Bitmap.createBitmap(pixels, QR_SIZE_PX, QR_SIZE_PX, Bitmap.Config.ARGB_8888).asImageBitmap()
}
