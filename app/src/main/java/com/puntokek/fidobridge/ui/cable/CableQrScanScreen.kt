package com.puntokek.fidobridge.ui.cable

import android.Manifest
import android.content.pm.PackageManager
import android.util.Log
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import com.puntokek.fidobridge.transport.cable.CableTransportService
import java.util.concurrent.Executors

/**
 * Screen for scanning a FIDO2 caBLE QR code to initiate a hybrid transport session.
 * Uses CameraX for preview and ML Kit for barcode detection.
 */
@Composable
fun CableQrScanScreen(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val cableStatus by CableTransportService.status.collectAsState()
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) ==
                    PackageManager.PERMISSION_GRANTED
        )
    }
    var hasBlePermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADVERTISE) ==
                    PackageManager.PERMISSION_GRANTED
        )
    }
    var manualInput by remember { mutableStateOf("") }
    var showManualInput by remember { mutableStateOf(false) }
    var lastScannedCode by remember { mutableStateOf<String?>(null) }
    var scanEnabled by remember { mutableStateOf(true) }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        hasCameraPermission = results[Manifest.permission.CAMERA] == true
        hasBlePermission = results[Manifest.permission.BLUETOOTH_ADVERTISE] == true
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "caBLE / Hybrid Transport",
            style = MaterialTheme.typography.headlineSmall
        )
        Spacer(modifier = Modifier.height(8.dp))
        Text(
            text = "Scan a FIDO2 QR code displayed by a browser or client to start " +
                    "a caBLE session over Bluetooth.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        Spacer(modifier = Modifier.height(16.dp))

        // Status indicator
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "Status: ",
                    style = MaterialTheme.typography.labelLarge
                )
                Text(
                    text = cableStatus,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        if (hasCameraPermission) {
            if (scanEnabled) {
                // Camera preview with QR scanning
                QrScannerView(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(300.dp),
                    onQrCodeScanned = { code ->
                        if (scanEnabled) {
                            scanEnabled = false
                            lastScannedCode = code
                            CableTransportService.startSessionFromQr(code)
                        }
                    }
                )
            } else {
                // Show last scanned code and option to re-scan
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer
                    )
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text(
                            text = "QR Code Detected",
                            style = MaterialTheme.typography.labelLarge
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = lastScannedCode?.take(60)?.plus("...") ?: "",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSecondaryContainer
                        )
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = {
                        scanEnabled = true
                        lastScannedCode = null
                    }) {
                        Text("Scan Again")
                    }
                    OutlinedButton(onClick = { CableTransportService.cancelSession() }) {
                        Text("Cancel Session")
                    }
                }
            }
        } else {
            Button(onClick = {
                permissionLauncher.launch(arrayOf(
                    Manifest.permission.CAMERA,
                    Manifest.permission.BLUETOOTH_ADVERTISE
                ))
            }) {
                Text("Grant Camera & Bluetooth Permissions")
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Toggle manual input
        TextButton(onClick = { showManualInput = !showManualInput }) {
            Text(if (showManualInput) "Hide manual input" else "Enter QR code manually")
        }

        if (showManualInput) {
            Spacer(modifier = Modifier.height(8.dp))
            OutlinedTextField(
                value = manualInput,
                onValueChange = { manualInput = it },
                label = { Text("QR code content") },
                placeholder = { Text("FIDO:/...") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        CableTransportService.startSessionFromQr(manualInput)
                        scanEnabled = false
                        lastScannedCode = manualInput
                    },
                    enabled = manualInput.isNotBlank()
                ) {
                    Text("Start Session")
                }
                OutlinedButton(onClick = { CableTransportService.cancelSession() }) {
                    Text("Cancel")
                }
            }
        }
    }
}

/**
 * CameraX preview with ML Kit barcode analysis for QR code scanning.
 */
@Composable
private fun QrScannerView(
    modifier: Modifier = Modifier,
    onQrCodeScanned: (String) -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val cameraExecutor = remember { Executors.newSingleThreadExecutor() }

    DisposableEffect(Unit) {
        onDispose { cameraExecutor.shutdown() }
    }

    AndroidView(
        modifier = modifier,
        factory = { ctx ->
            val previewView = PreviewView(ctx)

            val cameraProviderFuture = ProcessCameraProvider.getInstance(ctx)
            cameraProviderFuture.addListener({
                val cameraProvider = cameraProviderFuture.get()

                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }

                val imageAnalysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                val scanner = BarcodeScanning.getClient()

                imageAnalysis.setAnalyzer(cameraExecutor) { imageProxy ->
                    @androidx.annotation.OptIn(androidx.camera.core.ExperimentalGetImage::class)
                    val mediaImage = imageProxy.image
                    if (mediaImage != null) {
                        val inputImage = InputImage.fromMediaImage(
                            mediaImage,
                            imageProxy.imageInfo.rotationDegrees
                        )
                        scanner.process(inputImage)
                            .addOnSuccessListener { barcodes ->
                                for (barcode in barcodes) {
                                    if (barcode.format == Barcode.FORMAT_QR_CODE) {
                                        val rawValue = barcode.rawValue
                                        if (rawValue != null && rawValue.startsWith("FIDO:/", ignoreCase = true)) {
                                            Log.i("QrScanner", "Detected FIDO QR code")
                                            onQrCodeScanned(rawValue)
                                            return@addOnSuccessListener
                                        }
                                    }
                                }
                            }
                            .addOnCompleteListener {
                                imageProxy.close()
                            }
                    } else {
                        imageProxy.close()
                    }
                }

                try {
                    cameraProvider.unbindAll()
                    cameraProvider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        imageAnalysis
                    )
                } catch (e: Exception) {
                    Log.e("QrScanner", "Camera bind failed", e)
                }
            }, ContextCompat.getMainExecutor(ctx))

            previewView
        }
    )
}
