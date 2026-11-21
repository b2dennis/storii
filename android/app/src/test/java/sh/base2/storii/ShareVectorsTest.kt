package sh.base2.storii

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import sh.base2.storii.core.Crypto
import sh.base2.storii.core.DecryptionException
import sh.base2.storii.core.ShareCrypto
import sh.base2.storii.core.ShareMeta
import java.io.File

/** testdata/sharing.json, shared with Go, the extension and iOS. */
class ShareVectorsTest {
    private val v: JsonObject = Json.parseToJsonElement(File("../../testdata/sharing.json").readText()).jsonObject
    private fun s(k: String) = v[k]!!.jsonPrimitive.content
    private fun b(k: String) = Crypto.unb64(s(k))
    private fun n(x: Int) = ByteArray(12) { x.toByte() }

    /** Registration sends the whole KDF; it used to leave out the defaults, which the server rejects. */
    @Test fun kdfSentInFull() {
        val json = sh.base2.storii.core.StoriiJson.encodeToString(sh.base2.storii.core.Kdf.serializer(), sh.base2.storii.core.Kdf(salt = "c2FsdA=="))
        assertEquals("""{"alg":"argon2id","salt":"c2FsdA==","iterations":3,"memory_kib":65536,"parallelism":2}""", json)
    }

    @Test fun keys() {
        assertEquals(s("public_key"), Crypto.b64(ShareCrypto.publicKeyOf(b("private_key"))))
        assertEquals(s("sealed_private_key"), ShareCrypto.sealPrivateKey(b("vault_key"), b("private_key"), n(1)))
        assertArrayEquals(b("private_key"), ShareCrypto.openPrivateKey(b("vault_key"), s("sealed_private_key")))
        assertEquals(s("fingerprint"), ShareCrypto.fingerprint(b("public_key")))
    }

    @Test fun shareKeyAndItems() {
        val sid = s("share_id")
        assertEquals(s("wrapped_key"), ShareCrypto.wrapShareKey(b("public_key"), sid, b("share_key"), b("ephemeral_private_key"), n(2)))
        val key = ShareCrypto.unwrapShareKey(b("private_key"), sid, s("wrapped_key"))
        assertArrayEquals(b("share_key"), key)
        assertThrows(DecryptionException::class.java) { ShareCrypto.unwrapShareKey(b("private_key"), "other", s("wrapped_key")) }
        assertEquals(s("meta_data"), ShareCrypto.sealMeta(key, sid, ShareMeta("Family"), n(3)))
        assertEquals("Family", ShareCrypto.openMeta(key, sid, s("meta_data")).name)
        val item = ShareCrypto.decryptItem(key, sid, s("item_id"), s("item_data"))
        assertEquals("popcorn-Night-7", item.field("password"))
        assertThrows(DecryptionException::class.java) { ShareCrypto.decryptItem(key, sid, "other-id", s("item_data")) }
        // A fresh pair round-trips.
        val (priv, pub) = ShareCrypto.newKeyPair()
        assertArrayEquals(key, ShareCrypto.unwrapShareKey(priv, sid, ShareCrypto.wrapShareKey(pub, sid, key)))
    }
}
