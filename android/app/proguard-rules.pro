# kotlinx.serialization keeps what it needs through its plugin; BouncyCastle's Argon2 is used directly.
-dontwarn org.bouncycastle.**
-keep class org.bouncycastle.crypto.generators.Argon2BytesGenerator { *; }
-dontwarn org.slf4j.**
