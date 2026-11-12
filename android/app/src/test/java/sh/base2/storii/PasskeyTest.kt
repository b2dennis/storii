package sh.base2.storii

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.base2.storii.core.Passkey
import java.io.File
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/** testdata/passkey.json, a passkey made by the extension: Android must sign in with it exactly the same way. */
class PasskeyTest {
    private val v = Json.parseToJsonElement(File("../../testdata/passkey.json").readText()).jsonObject
    private fun s(k: String) = v.getValue(k).jsonPrimitive.content

    private fun verify(spki: ByteArray, authData: ByteArray, hash: ByteArray, sig: ByteArray) =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))); update(authData); update(hash); verify(sig)
        }

    @Test
    fun signsInWithTheExtensionsPasskey() {
        val fields = v.getValue("passkey").jsonObject.mapValues { it.value.jsonPrimitive.content }
        val a = Passkey.assert(fields, s("origin"), s("challenge"))
        assertEquals(s("client_data_json"), Passkey.b64u(a.clientDataJSON))
        assertEquals(s("authenticator_data"), Passkey.b64u(a.authenticatorData))
        assertTrue(verify(Passkey.unb64u(s("public_key")), a.authenticatorData, MessageDigest.getInstance("SHA-256").digest(a.clientDataJSON), a.signature))
    }

    @Test
    fun createdPasskeysSignIn() {
        val c = Passkey.create("example.com", "https://example.com", "Y2hhbGxlbmdl", "BwcH", "me", "Me")
        val resp = Json.parseToJsonElement(c.responseJson).jsonObject.getValue("response").jsonObject
        val spki = Passkey.unb64u(resp.getValue("publicKey").jsonPrimitive.content)
        val hash = MessageDigest.getInstance("SHA-256").digest("browser client data".toByteArray())
        val a = Passkey.assert(c.fields, "https://example.com", "abc", hash)
        assertTrue(verify(spki, a.authenticatorData, hash, a.signature))
    }

    @Test
    fun rpIds() {
        assertTrue(Passkey.rpIdAllowed("example.com", "https://login.example.com"))
        assertTrue(Passkey.rpIdAllowed("localhost", "http://localhost:8080"))
        assertFalse(Passkey.rpIdAllowed("example.com", "http://example.com"))
        assertFalse(Passkey.rpIdAllowed("co.uk", "https://shop.co.uk"))
        assertFalse(Passkey.rpIdAllowed("ample.com", "https://example.com"))
    }
}
