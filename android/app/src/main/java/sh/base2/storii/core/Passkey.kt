package sh.base2.storii.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.sec.ECPrivateKey
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.URI
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey as JcaECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * Passkeys with storii as the authenticator, as the browser extension's src/lib/passkey.js (shared vector:
 * testdata/passkey.json): ES256, attestation "none", backed up and synced (BE and BS flags), sign count 0.
 */
object Passkey {
    private val AAGUID = "d1a8c0b05f2e4c3b9a7e73746f726969".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private const val FLAGS = 0x01 or 0x04 or 0x08 or 0x10 // user present, user verified, backup eligible, backed up

    fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    fun unb64u(s: String): ByteArray = Base64.getUrlDecoder().decode(s.trimEnd('='))
    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    /** The CBOR WebAuthn needs: ints, byte and text strings, maps (entries in the order given). */
    fun cbor(v: Any): ByteArray {
        val out = ByteArrayOutputStream()
        fun head(major: Int, n: Long) {
            when {
                n < 24 -> out.write((major shl 5) or n.toInt())
                n < 256 -> { out.write((major shl 5) or 24); out.write(n.toInt()) }
                n < 65536 -> { out.write((major shl 5) or 25); out.write((n shr 8).toInt()); out.write((n and 255).toInt()) }
                else -> { out.write((major shl 5) or 26); for (s in 24 downTo 0 step 8) out.write(((n shr s) and 255).toInt()) }
            }
        }
        fun enc(x: Any) {
            when (x) {
                is Int -> if (x >= 0) head(0, x.toLong()) else head(1, (-1 - x).toLong())
                is String -> x.toByteArray().let { head(3, it.size.toLong()); out.write(it) }
                is ByteArray -> { head(2, x.size.toLong()); out.write(x) }
                is List<*> -> { head(5, x.size.toLong()); for (p in x) { val (k, value) = p as Pair<*, *>; enc(k!!); enc(value!!) } }
                else -> error("cbor: unsupported value")
            }
        }
        enc(v)
        return out.toByteArray()
    }

    /** Whether a page at [origin] may use [rpId]: https (or http://localhost), rpId its host or a registrable parent. */
    fun rpIdAllowed(rpId: String, origin: String): Boolean {
        val u = runCatching { URI(origin) }.getOrNull() ?: return false
        val host = u.host ?: return false
        if (u.scheme != "https" && !(u.scheme == "http" && (host == "localhost" || host.endsWith(".localhost")))) return false
        if (rpId.isEmpty() || (host != rpId && !host.endsWith(".$rpId"))) return false
        if (host == rpId) return true
        val labels = rpId.split('.')
        return labels.size >= 2 && !(labels.size == 2 && labels[0].length <= 3 && labels[1].length == 2)
    }

    private fun clientData(type: String, challenge: String, origin: String) = Json.encodeToString(buildJsonObject {
        put("type", type); put("challenge", challenge); put("origin", origin); put("crossOrigin", false)
    }).toByteArray()

    private fun unsigned32(n: BigInteger): ByteArray = n.toByteArray().let { b ->
        when { b.size == 32 -> b; b.size > 32 -> b.copyOfRange(b.size - 32, b.size); else -> ByteArray(32 - b.size) + b }
    }

    /** PKCS#8 with the public key inside (WebCrypto in the extension imports it the same way). */
    private fun pkcs8(priv: JcaECPrivateKey, pub: ECPublicKey): ByteArray {
        val point = byteArrayOf(4) + unsigned32(pub.w.affineX) + unsigned32(pub.w.affineY)
        val ec = ECPrivateKey(256, priv.s, DERBitString(point), null)
        return PrivateKeyInfo(AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, X9ObjectIdentifiers.prime256v1), ec).encoded
    }

    class Created(val fields: Map<String, String>, val responseJson: String)

    /**
     * A new passkey. [challenge] and [userId] are base64url. With [clientDataHash] (a browser that builds the client
     * data itself) nothing is signed anyway: attestation is "none".
     */
    fun create(rpId: String, origin: String, challenge: String, userId: String, userName: String, displayName: String): Created {
        val kp = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val pub = kp.public as ECPublicKey
        val cose = cbor(listOf(1 to 2, 3 to -7, -1 to 1, -2 to unsigned32(pub.w.affineX), -3 to unsigned32(pub.w.affineY)))
        val credId = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val authData = sha256(rpId.toByteArray()) + byteArrayOf((FLAGS or 0x40).toByte(), 0, 0, 0, 0) + AAGUID +
            byteArrayOf(0, credId.size.toByte()) + credId + cose
        val attestation = cbor(listOf("fmt" to "none", "attStmt" to emptyList<Pair<String, Any>>(), "authData" to authData))
        val cd = clientData("webauthn.create", challenge, origin)
        val fields = mapOf("credential_id" to b64u(credId), "rp_id" to rpId, "user_handle" to userId, "user_name" to userName,
            "user_display_name" to displayName, "private_key" to b64u(pkcs8(kp.private as JcaECPrivateKey, pub)))
        val json = buildJsonObject {
            put("id", b64u(credId)); put("rawId", b64u(credId)); put("type", "public-key"); put("authenticatorAttachment", "platform")
            putJsonObject("response") {
                put("clientDataJSON", b64u(cd)); put("attestationObject", b64u(attestation)); put("authenticatorData", b64u(authData))
                put("publicKey", b64u(pub.encoded)); put("publicKeyAlgorithm", -7)
                putJsonArray("transports") { add("hybrid"); add("internal") }
            }
            putJsonObject("clientExtensionResults") { putJsonObject("credProps") { put("rk", true) } }
        }
        return Created(fields, Json.encodeToString(json))
    }

    class Assertion(val clientDataJSON: ByteArray, val authenticatorData: ByteArray, val signature: ByteArray, val json: String)

    /** A sign-in. With [clientDataHash] (from a browser) that hash is signed instead of storii's own client data. */
    fun assert(fields: Map<String, String>, origin: String, challenge: String, clientDataHash: ByteArray? = null): Assertion {
        val authData = sha256(fields.getValue("rp_id").toByteArray()) + byteArrayOf(FLAGS.toByte(), 0, 0, 0, 0)
        val cd = clientData("webauthn.get", challenge, origin)
        val key = KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(unb64u(fields.getValue("private_key"))))
        val sig = Signature.getInstance("SHA256withECDSA").run {
            initSign(key); update(authData); update(clientDataHash ?: sha256(cd)); sign()
        }
        val id = fields.getValue("credential_id")
        val json = buildJsonObject {
            put("id", id); put("rawId", id); put("type", "public-key"); put("authenticatorAttachment", "platform")
            putJsonObject("response") {
                put("clientDataJSON", b64u(cd)); put("authenticatorData", b64u(authData)); put("signature", b64u(sig))
                fields["user_handle"]?.takeIf { it.isNotEmpty() }?.let { put("userHandle", it) } ?: put("userHandle", JsonPrimitive(null as String?))
            }
            putJsonObject("clientExtensionResults") {}
        }
        return Assertion(cd, authData, sig, Json.encodeToString(json))
    }
}
