package sh.base2.storii.data

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Fingerprint / face unlock: the vault key is encrypted with an Android Keystore key that can only be used right after a
 * strong biometric check, and is invalidated when biometrics are enrolled or removed.
 */
object Biometric {
    private const val KEY = "storii-vault-key"
    private const val PREFS = "biometric"

    fun available(ctx: Context) =
        BiometricManager.from(ctx).canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun enabled(ctx: Context) = prefs(ctx).contains("ct")

    fun forget(ctx: Context) {
        prefs(ctx).edit { clear() }
        runCatching { KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(KEY) }
    }

    private fun secretKey(create: Boolean): SecretKey? {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(KEY, null) as? SecretKey)?.let { if (!create) return it }
        if (!create) return null
        val spec = KeyGenParameterSpec.Builder(KEY, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                else @Suppress("DEPRECATION") setUserAuthenticationValidityDurationSeconds(-1)
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
    }

    private suspend fun prompt(activity: FragmentActivity, cipher: Cipher, title: String, negative: String): Cipher =
        suspendCancellableCoroutine { cont ->
            val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (cont.isActive) cont.resume(result.cryptoObject!!.cipher!!)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (cont.isActive) cont.resumeWithException(BiometricCancelled(errString.toString()))
                }
            })
            prompt.authenticate(
                BiometricPrompt.PromptInfo.Builder().setTitle(title).setNegativeButtonText(negative)
                    .setAllowedAuthenticators(BIOMETRIC_STRONG).build(),
                BiometricPrompt.CryptoObject(cipher),
            )
            cont.invokeOnCancellation { prompt.cancelAuthentication() }
        }

    /** Stores the vault key for biometric unlock (asks for a fingerprint once). */
    suspend fun enable(activity: FragmentActivity, vaultKey: ByteArray) {
        forget(activity)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, secretKey(create = true)) }
        val done = prompt(activity, cipher, "Turn on biometric unlock", "Cancel")
        val ct = done.doFinal(vaultKey)
        val enc = Base64.getEncoder()
        prefs(activity).edit { putString("iv", enc.encodeToString(done.iv)); putString("ct", enc.encodeToString(ct)) }
    }

    /** Returns the vault key after a successful biometric check, or null when biometrics changed and it is gone. */
    suspend fun unlock(activity: FragmentActivity): ByteArray? {
        val p = prefs(activity)
        val dec = Base64.getDecoder()
        val iv = p.getString("iv", null) ?: return null
        val ct = p.getString("ct", null) ?: return null
        val key = secretKey(create = false) ?: return null.also { forget(activity) }
        val cipher = try {
            Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, dec.decode(iv))) }
        } catch (e: KeyPermanentlyInvalidatedException) {
            forget(activity)
            return null
        }
        return prompt(activity, cipher, "Unlock storii", "Use master password").doFinal(dec.decode(ct))
    }
}

class BiometricCancelled(message: String) : Exception(message)
