# kotlinx.serialization keeps what it needs through its plugin; BouncyCastle's Argon2 is used directly.
-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-dontwarn org.slf4j.**

# ML Kit finds its components by reflection (registrars named in the manifest, created through their no-arg
# constructors). Without these, R8's full mode strips what it can't see used and BarcodeScanning.getClient() crashes
# in release builds only.
-keep class * implements com.google.firebase.components.ComponentRegistrar { <init>(); }
-keep class com.google.mlkit.** { *; }

# Credential transfer (import from another app): providerevents finds its Play services implementation by the class
# name in its manifest meta-data and ships no keep rules, so release builds lost it ("no provider dependencies found").
-keep class androidx.credentials.providerevents.** { *; }
