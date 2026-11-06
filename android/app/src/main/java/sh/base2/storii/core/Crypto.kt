package sh.base2.storii.core

import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.security.SecureRandom
import java.text.Normalizer
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class DecryptionException : Exception("decryption failed (wrong master password or corrupted data)")

/** storii v2 crypto (docs/CRYPTO.md), pinned by testdata/vectors.json. */
object Crypto {
    private val random = SecureRandom()

    class Keys(val auth: ByteArray, val wrap: ByteArray) {
        val authKey: String get() = b64(auth)
    }

    fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
    fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)
    fun randomBytes(n: Int) = ByteArray(n).also { random.nextBytes(it) }

    fun newKdf() = Kdf(salt = b64(randomBytes(16)))

    /** Argon2id over the NFC-normalized password, split with HKDF-SHA256. Slow on purpose (about a second). */
    fun deriveKeys(password: String, kdf: Kdf): Keys {
        require(kdf.alg == "argon2id") { "unsupported kdf ${kdf.alg}" }
        val params = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(kdf.iterations)
            .withMemoryAsKB(kdf.memoryKib)
            .withParallelism(kdf.parallelism)
            .withSalt(unb64(kdf.salt))
            .build()
        val master = ByteArray(32)
        Argon2BytesGenerator().apply { init(params) }
            .generateBytes(Normalizer.normalize(password, Normalizer.Form.NFC).toByteArray(Charsets.UTF_8), master)
        return Keys(hkdf(master, "storii auth"), hkdf(master, "storii wrap"))
    }

    private fun hmac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }.doFinal(data)

    /** RFC 5869 with an empty salt and one 32-byte block. */
    fun hkdf(ikm: ByteArray, info: String): ByteArray {
        val prk = hmac(ByteArray(32), ikm)
        return hmac(prk, info.toByteArray() + byteArrayOf(1))
    }

    /** base64(0x01 || nonce(12) || ciphertext || tag(16)) */
    fun seal(key: ByteArray, plaintext: ByteArray, aad: String, nonce: ByteArray = randomBytes(12)): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad.toByteArray())
        return b64(byteArrayOf(1) + nonce + c.doFinal(plaintext))
    }

    fun open(key: ByteArray, data: String, aad: String): ByteArray {
        val raw = try {
            unb64(data)
        } catch (e: IllegalArgumentException) {
            throw DecryptionException()
        }
        if (raw.size < 29 || raw[0] != 1.toByte()) throw DecryptionException()
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, raw, 1, 12))
            c.updateAAD(aad.toByteArray())
            c.doFinal(raw, 13, raw.size - 13)
        } catch (e: java.security.GeneralSecurityException) {
            throw DecryptionException()
        }
    }

    fun wrapVaultKey(wrap: ByteArray, vaultKey: ByteArray, nonce: ByteArray = randomBytes(12)) =
        seal(wrap, vaultKey, "storii:vault-key", nonce)

    fun unwrapVaultKey(wrap: ByteArray, wrapped: String): ByteArray =
        open(wrap, wrapped, "storii:vault-key").also { if (it.size != 32) throw DecryptionException() }

    fun encryptItem(vaultKey: ByteArray, id: String, item: Item, nonce: ByteArray = randomBytes(12)) =
        seal(vaultKey, StoriiJson.encodeToString(Item.serializer(), item).toByteArray(), "storii:item:$id", nonce)

    fun encryptRaw(vaultKey: ByteArray, id: String, plaintext: String, nonce: ByteArray) =
        seal(vaultKey, plaintext.toByteArray(), "storii:item:$id", nonce)

    fun decryptItem(vaultKey: ByteArray, id: String, data: String): Item =
        StoriiJson.decodeFromString(Item.serializer(), String(open(vaultKey, data, "storii:item:$id")))
}
