# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# BouncyCastle — used for attestation certificate generation
-keep class org.bouncycastle.** { *; }
-dontwarn org.bouncycastle.**

# Keep HostApduService (instantiated by system via manifest)
-keep class com.puntokek.fidobridge.transport.FidoNfcService { *; }

# Keep Application subclass
-keep class com.puntokek.fidobridge.FidoBridgeApplication { *; }

# Keep activities referenced from manifest
-keep class com.puntokek.fidobridge.bridge.CredentialBridgeActivity { *; }
-keep class com.puntokek.fidobridge.MainActivity { *; }