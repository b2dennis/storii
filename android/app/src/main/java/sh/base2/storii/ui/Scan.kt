package sh.base2.storii.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.compose.CameraXViewfinder
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.core.SurfaceRequest
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.lifecycle.awaitInstance
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Image
import androidx.compose.material3.OutlinedButton
import androidx.activity.result.PickVisualMediaRequest
import android.content.Context
import android.net.Uri
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.navigation.NavController
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import kotlinx.coroutines.awaitCancellation
import java.util.concurrent.Executors

/** Scans a 2FA QR code (otpauth://) and hands the URI back to the edit screen. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(nav: NavController) {
    val ctx = LocalContext.current
    var granted by remember { mutableStateOf(ContextCompat.checkSelfPermission(ctx, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted = it }
    var hint by remember { mutableStateOf("Point the camera at the QR code the site shows when you turn on 2FA.") }
    var done by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { if (!granted) ask.launch(Manifest.permission.CAMERA) }

    fun onCode(raw: String) {
        if (done) return
        if (!raw.startsWith("otpauth://totp/", ignoreCase = true)) {
            hint = "That QR code isn't a 2FA setup code."
            return
        }
        done = true
        nav.previousBackStackEntry?.savedStateHandle?.set("otpauth", raw)
        nav.popBackStack()
    }

    // A screenshot or saved image of the QR code: the photo picker needs no permission.
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri != null) qrCodesInImage(ctx, uri) { codes ->
            val link = codes.firstOrNull { it.startsWith("otpauth://totp/", ignoreCase = true) }
            when {
                link != null -> onCode(link)
                codes.isEmpty() -> hint = "No QR code found in that image. Crop the screenshot to the QR code and try again."
                else -> hint = "That QR code isn't a 2FA setup code."
            }
        }
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text("Scan 2FA QR code") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            Text(hint, Modifier.padding(16.dp))
            OutlinedButton(onClick = { pick.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly)) },
                Modifier.padding(horizontal = 16.dp).padding(bottom = 16.dp).fillMaxWidth()) {
                Icon(Icons.Default.Image, null, Modifier.padding(end = 8.dp))
                Text("Choose screenshot or image")
            }
            if (granted) Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                QrCamera(::onCode)
                Box(Modifier.size(240.dp).border(3.dp, Color.White, RoundedCornerShape(20.dp)))
            } else Text("storii needs the camera to scan QR codes. You can also choose a screenshot of the QR code, or type the setup key instead.", Modifier.padding(16.dp))
        }
    }
}

@androidx.annotation.OptIn(ExperimentalGetImage::class)
@Composable
private fun QrCamera(onCode: (String) -> Unit) {
    val ctx = LocalContext.current
    val owner = LocalLifecycleOwner.current
    var request by remember { mutableStateOf<SurfaceRequest?>(null) }
    LaunchedEffect(Unit) {
        val provider = ProcessCameraProvider.awaitInstance(ctx)
        val preview = Preview.Builder().build().apply { setSurfaceProvider { request = it } }
        val scanner = BarcodeScanning.getClient(BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
        val executor = Executors.newSingleThreadExecutor()
        val analysis = ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build().apply {
            setAnalyzer(executor) { proxy ->
                val image = proxy.image
                if (image == null) {
                    proxy.close()
                    return@setAnalyzer
                }
                scanner.process(InputImage.fromMediaImage(image, proxy.imageInfo.rotationDegrees))
                    .addOnSuccessListener { codes -> codes.firstNotNullOfOrNull { it.rawValue }?.let { v -> ContextCompat.getMainExecutor(ctx).execute { onCode(v) } } }
                    .addOnCompleteListener { proxy.close() }
            }
        }
        provider.unbindAll()
        provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
        try {
            awaitCancellation()
        } finally {
            provider.unbindAll()
            scanner.close()
            executor.shutdown()
        }
    }
    request?.let { CameraXViewfinder(it, Modifier.fillMaxSize()) }
}

/** Reads every QR code in an image (e.g. a screenshot of a site's 2FA setup page). */
internal fun qrCodesInImage(ctx: Context, uri: Uri, done: (List<String>) -> Unit) {
    val image = runCatching { InputImage.fromFilePath(ctx, uri) }.getOrElse { done(emptyList()); return }
    val scanner = BarcodeScanning.getClient(BarcodeScannerOptions.Builder().setBarcodeFormats(Barcode.FORMAT_QR_CODE).build())
    scanner.process(image)
        .addOnSuccessListener { codes -> done(codes.mapNotNull { it.rawValue }) }
        .addOnFailureListener { done(emptyList()) }
        .addOnCompleteListener { scanner.close() }
}
