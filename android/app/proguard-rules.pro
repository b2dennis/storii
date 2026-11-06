# kotlinx.serialization keeps what it needs through its plugin; BouncyCastle's Argon2 is used directly.
-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-dontwarn org.slf4j.**

# ML Kit finds its components by reflection (registrars named in the manifest, created through their no-arg
# constructors). Without these, R8's full mode strips what it can't see used and BarcodeScanning.getClient() crashes
# in release builds only.
-keep class * implements com.google.firebase.components.ComponentRegistrar { <init>(); }
-keep class com.google.mlkit.** { *; }
