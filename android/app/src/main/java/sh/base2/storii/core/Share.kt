package sh.base2.storii.core

import kotlinx.serialization.Serializable
import org.bouncycastle.math.ec.rfc7748.X25519
import java.security.MessageDigest

/** The decrypted description of a share. */
@Serializable
data class ShareMeta(val name: String)

/** Sharing crypto (docs/CRYPTO.md#sharing), pinned by testdata/sharing.json. */
object ShareCrypto {
    fun publicKeyOf(priv: ByteArray) = ByteArray(32).also { X25519.scalarMultBase(priv, 0, it, 0) }

    /** A new X25519 key pair: (private, public). */
    fun newKeyPair(): Pair<ByteArray, ByteArray> = Crypto.randomBytes(32).let { it to publicKeyOf(it) }

    fun sealPrivateKey(vaultKey: ByteArray, priv: ByteArray, nonce: ByteArray = Crypto.randomBytes(12)) =
        Crypto.seal(vaultKey, priv, "storii:share-private-key", nonce)

    fun openPrivateKey(vaultKey: ByteArray, sealed: String): ByteArray =
        Crypto.open(vaultKey, sealed, "storii:share-private-key").also { if (it.size != 32) throw DecryptionException() }

    /** The first 16 bytes of SHA-256(public key), as 8 groups of 4 hex digits. */
    fun fingerprint(pub: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(pub).take(16).joinToString("") { "%02x".format(it) }.chunked(4).joinToString(" ")

    private fun agree(priv: ByteArray, pub: ByteArray): ByteArray {
        val out = ByteArray(32)
        if (pub.size != 32 || !X25519.calculateAgreement(priv, 0, pub, 0, out, 0)) throw DecryptionException()
        return out
    }

    private fun wrapKey(shared: ByteArray, ephPub: ByteArray, recipientPub: ByteArray) =
        Crypto.hkdf(shared + ephPub + recipientPub, "storii share key")

    /** The share key for one member: "base64(ephemeral public key).envelope". */
    fun wrapShareKey(recipientPub: ByteArray, shareId: String, shareKey: ByteArray,
                     eph: ByteArray = Crypto.randomBytes(32), nonce: ByteArray = Crypto.randomBytes(12)): String {
        val ephPub = publicKeyOf(eph)
        val key = wrapKey(agree(eph, recipientPub), ephPub, recipientPub)
        return Crypto.b64(ephPub) + "." + Crypto.seal(key, shareKey, "storii:share-key:$shareId", nonce)
    }

    fun unwrapShareKey(priv: ByteArray, shareId: String, wrapped: String): ByteArray {
        val dot = wrapped.indexOf('.')
        if (dot < 0) throw DecryptionException()
        val ephPub = runCatching { Crypto.unb64(wrapped.substring(0, dot)) }.getOrElse { throw DecryptionException() }
        val key = wrapKey(agree(priv, ephPub), ephPub, publicKeyOf(priv))
        return Crypto.open(key, wrapped.substring(dot + 1), "storii:share-key:$shareId").also { if (it.size != 32) throw DecryptionException() }
    }

    fun sealMeta(shareKey: ByteArray, shareId: String, meta: ShareMeta, nonce: ByteArray = Crypto.randomBytes(12)) =
        Crypto.seal(shareKey, StoriiJson.encodeToString(ShareMeta.serializer(), meta).toByteArray(), "storii:share:$shareId", nonce)

    fun openMeta(shareKey: ByteArray, shareId: String, data: String): ShareMeta =
        StoriiJson.decodeFromString(ShareMeta.serializer(), String(Crypto.open(shareKey, data, "storii:share:$shareId")))

    private fun itemAad(shareId: String, id: String) = "storii:share:$shareId:item:$id"

    fun encryptItem(shareKey: ByteArray, shareId: String, id: String, item: Item, nonce: ByteArray = Crypto.randomBytes(12)) =
        Crypto.seal(shareKey, StoriiJson.encodeToString(Item.serializer(), item).toByteArray(), itemAad(shareId, id), nonce)

    fun encryptRaw(shareKey: ByteArray, shareId: String, id: String, plaintext: ByteArray) =
        Crypto.seal(shareKey, plaintext, itemAad(shareId, id))

    fun openItem(shareKey: ByteArray, shareId: String, id: String, data: String): ByteArray = Crypto.open(shareKey, data, itemAad(shareId, id))

    fun decryptItem(shareKey: ByteArray, shareId: String, id: String, data: String): Item =
        StoriiJson.decodeFromString(Item.serializer(), String(openItem(shareKey, shareId, id, data)))
}
