package com.nexa.pipe.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import android.util.Size
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.core.resolutionselector.ResolutionSelector
import androidx.camera.core.resolutionselector.ResolutionStrategy
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size as ComposeSize
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

/** Hint and error colors readable on top of the camera preview in both themes. */
private val ScannerTextColor = Color.White
private val ScannerErrorColor = Color(0xFFFF8A80)

/**
 * Full-screen dialog that scans a QR code with the back camera.
 *
 * [onResult] receives the decoded text and returns null when the code was
 * accepted — the dialog closes itself — or a message that is shown while the
 * camera keeps scanning. This mirrors the `(String) -> String?` contract used
 * by the node dialogs, so the caller decides what a valid code looks like.
 */
@Composable
fun QrScannerDialog(
    onDismiss: () -> Unit,
    onResult: (String) -> String?
) {
    val context = LocalContext.current
    var permissionGranted by remember { mutableStateOf(context.hasCameraPermission()) }
    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted -> permissionGranted = granted }

    LaunchedEffect(Unit) {
        if (!permissionGranted) permissionLauncher.launch(Manifest.permission.CAMERA)
    }

    Dialog(
        onDismissRequest = onDismiss,
        // The camera preview is drawn edge to edge; only the controls are inset
        // (see statusBarsPadding / navigationBarsPadding below).
        properties = DialogProperties(
            usePlatformDefaultWidth = false,
            decorFitsSystemWindows = false
        )
    ) {
        Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
            if (permissionGranted) {
                ScannerContent(onResult = onResult, onClose = onDismiss)
            } else {
                CameraPermissionRequest(
                    onRequest = { permissionLauncher.launch(Manifest.permission.CAMERA) },
                    onClose = onDismiss
                )
            }
        }
    }
}

@Composable
private fun ScannerContent(
    onResult: (String) -> String?,
    onClose: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember {
        PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER }
    }
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }

    // The analyzer outlives individual recompositions, so everything it touches
    // is kept in stable holders instead of captured values.
    val handled = remember { AtomicBoolean(false) }
    val status = remember { mutableStateOf<String?>(null) }
    val currentOnResult = rememberUpdatedState(onResult)
    val currentOnClose = rememberUpdatedState(onClose)
    // The analyzer callback arrives on the camera analysis thread, but the
    // callbacks write Compose state (and may toast); hop to the main thread
    // before touching any of it.
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    val analyzer = remember {
        QrCodeAnalyzer { text ->
            if (!handled.get()) {
                mainHandler.post {
                    if (!handled.get()) {
                        val message = currentOnResult.value(text)
                        if (message == null) {
                            handled.set(true)
                            currentOnClose.value()
                        } else {
                            status.value = message
                        }
                    }
                }
            }
        }
    }

    var camera by remember { mutableStateOf<Camera?>(null) }
    var cameraError by remember { mutableStateOf<String?>(null) }
    var torchEnabled by remember { mutableStateOf(false) }

    DisposableEffect(lifecycleOwner) {
        val providerFuture = ProcessCameraProvider.getInstance(context)
        providerFuture.addListener(
            {
                try {
                    val provider = providerFuture.get()

                    val preview = Preview.Builder().build().apply {
                        setSurfaceProvider(previewView.surfaceProvider)
                    }

                    // A modest resolution is enough for QR codes and keeps the
                    // per-frame decode well under the frame interval.
                    val analysis = ImageAnalysis.Builder()
                        .setResolutionSelector(
                            ResolutionSelector.Builder()
                                .setResolutionStrategy(
                                    ResolutionStrategy(
                                        Size(1280, 720),
                                        ResolutionStrategy.FALLBACK_RULE_CLOSEST_LOWER_THEN_HIGHER
                                    )
                                )
                                .build()
                        )
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                        .apply { setAnalyzer(analysisExecutor, analyzer) }

                    provider.unbindAll()
                    camera = provider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        analysis
                    )
                } catch (e: Exception) {
                    // No back camera, camera already in use, ...
                    cameraError = e.message ?: "Unable to start the camera"
                }
            },
            ContextCompat.getMainExecutor(context)
        )

        onDispose {
            runCatching { if (providerFuture.isDone) providerFuture.get().unbindAll() }
            analysisExecutor.shutdown()
        }
    }

    Box(modifier = Modifier.fillMaxSize()) {
        AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())

        ScannerOverlay(modifier = Modifier.fillMaxSize())

        IconButton(
            onClick = onClose,
            modifier = Modifier
                .align(Alignment.TopEnd)
                .statusBarsPadding()
                .padding(16.dp)
        ) {
            Icon(Icons.Default.Close, contentDescription = "Close scanner", tint = ScannerTextColor)
        }

        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .navigationBarsPadding()
                .padding(start = 32.dp, end = 32.dp, bottom = 112.dp)
        ) {
            val message = when {
                cameraError != null -> cameraError
                status.value != null -> status.value
                else -> "Point the camera at an otpauth:// QR code"
            }
            Text(
                text = message ?: "",
                color = if (cameraError != null || status.value != null) ScannerErrorColor else ScannerTextColor,
                style = MaterialTheme.typography.bodySmall,
                textAlign = TextAlign.Center
            )
        }

        if (cameraError == null) {
            TextButton(
                onClick = {
                    val target = !torchEnabled
                    torchEnabled = target
                    runCatching { camera?.cameraControl?.enableTorch(target) }
                },
                colors = ButtonDefaults.textButtonColors(contentColor = ScannerTextColor),
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .navigationBarsPadding()
                    .padding(bottom = 56.dp)
            ) {
                Text(if (torchEnabled) "Turn torch off" else "Turn torch on")
            }
        }
    }
}

/** Dims everything but the scanning frame and draws its outline. */
@Composable
private fun ScannerOverlay(modifier: Modifier = Modifier) {
    Canvas(modifier = modifier) {
        val side = min(size.width, size.height) * 0.7f
        val left = (size.width - side) / 2f
        val top = (size.height - side) / 2f
        val scrim = Color.Black.copy(alpha = 0.55f)

        // Four rectangles instead of a cut-out: no layer or blend mode is
        // needed and the preview stays fully live inside the frame.
        drawRect(scrim, topLeft = Offset(0f, 0f), size = ComposeSize(size.width, top))
        drawRect(
            scrim,
            topLeft = Offset(0f, top + side),
            size = ComposeSize(size.width, (size.height - top - side).coerceAtLeast(0f))
        )
        drawRect(scrim, topLeft = Offset(0f, top), size = ComposeSize(left, side))
        drawRect(
            scrim,
            topLeft = Offset(left + side, top),
            size = ComposeSize((size.width - left - side).coerceAtLeast(0f), side)
        )

        val radius = CornerRadius(16.dp.toPx(), 16.dp.toPx())
        drawRoundRect(
            color = Color.White,
            topLeft = Offset(left, top),
            size = ComposeSize(side, side),
            cornerRadius = radius,
            style = Stroke(width = 3.dp.toPx())
        )
    }
}

@Composable
private fun CameraPermissionRequest(onRequest: () -> Unit, onClose: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp)
    ) {
        Spacer(modifier = Modifier.weight(1f))
        Text(
            text = "Camera access is required to scan a QR code.",
            color = ScannerTextColor,
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(16.dp))
        Button(onClick = onRequest) {
            Text("Grant permission")
        }
        TextButton(onClick = onClose) {
            Text("Cancel", color = ScannerTextColor)
        }
        Spacer(modifier = Modifier.weight(1f))
    }
}

private fun Context.hasCameraPermission(): Boolean =
    ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
        PackageManager.PERMISSION_GRANTED

/** A contiguous luminance plane, ready to be handed to ZXing. */
private class Luminance(val data: ByteArray, val width: Int, val height: Int)

/**
 * Decodes QR codes from the luma plane of the analysis frames.
 *
 * Only the Y plane is used: ZXing needs luminance anyway, so converting to RGB
 * would only cost time.
 */
private class QrCodeAnalyzer(private val onDecoded: (String) -> Unit) : ImageAnalysis.Analyzer {

    private val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }

    override fun analyze(image: ImageProxy) {
        try {
            val luminance = image.luminance() ?: return
            val upright = luminance.rotated(image.imageInfo.rotationDegrees)
            val source = PlanarYUVLuminanceSource(
                upright.data,
                upright.width,
                upright.height,
                0,
                0,
                upright.width,
                upright.height,
                false
            )
            val result = reader.decodeWithState(BinaryBitmap(HybridBinarizer(source)))
            if (result != null) onDecoded(result.text)
        } catch (notFound: NotFoundException) {
            // No QR code in this frame; keep scanning.
        } catch (e: Exception) {
            // Decoding is best effort, malformed frames are simply skipped.
        } finally {
            reader.reset()
            image.close()
        }
    }
}

/**
 * Copies the luma plane into a tightly packed array. The plane's row stride is
 * usually padded for hardware alignment and cannot be used directly.
 */
private fun ImageProxy.luminance(): Luminance? {
    val plane = planes.firstOrNull() ?: return null
    if (plane.pixelStride != 1) return null

    val buffer = plane.buffer
    val rowStride = plane.rowStride
    val data = ByteArray(width * height)

    buffer.rewind()
    if (rowStride == width) {
        if (buffer.remaining() < data.size) return null
        buffer.get(data, 0, data.size)
        return Luminance(data, width, height)
    }

    val row = ByteArray(rowStride)
    var offset = 0
    for (y in 0 until height) {
        val available = minOf(rowStride, buffer.remaining())
        if (available < width) return null
        buffer.get(row, 0, available)
        System.arraycopy(row, 0, data, offset, width)
        offset += width
    }
    return Luminance(data, width, height)
}

/** Rotates the buffer clockwise so the framed image is upright. */
private fun Luminance.rotated(degrees: Int): Luminance {
    val normalized = ((degrees % 360) + 360) % 360
    if (normalized == 0 || width == 0 || height == 0) return this

    val output = ByteArray(width * height)
    return when (normalized) {
        90 -> {
            for (y in 0 until height) {
                for (x in 0 until width) {
                    output[x * height + (height - 1 - y)] = data[y * width + x]
                }
            }
            Luminance(output, height, width)
        }

        180 -> {
            for (y in 0 until height) {
                for (x in 0 until width) {
                    output[(height - 1 - y) * width + (width - 1 - x)] = data[y * width + x]
                }
            }
            Luminance(output, width, height)
        }

        270 -> {
            for (y in 0 until height) {
                for (x in 0 until width) {
                    output[(width - 1 - x) * height + y] = data[y * width + x]
                }
            }
            Luminance(output, height, width)
        }

        else -> this
    }
}
