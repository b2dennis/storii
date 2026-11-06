package sh.base2.storii

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import sh.base2.storii.core.Crypto
import sh.base2.storii.core.DecryptionException
import sh.base2.storii.core.Kdf
import sh.base2.storii.core.Match
import sh.base2.storii.core.StoriiJson
import sh.base2.storii.core.Totp
import java.io.File

/** testdata/vectors.json, shared with the Go server/CLI, the browser extension and iOS. */
class VectorsTest {
    private val v: JsonObject = Json.parseToJsonElement(File("../../testdata/vectors.json").readText()).jsonObject
    private fun JsonObject.s(k: String) = this[k]!!.jsonPrimitive.content
    private fun JsonObject.map(k: String) = this[k]!!.jsonObject.mapValues { it.value.jsonPrimitive.content }

    @Test fun kdf() {
        for (k in v["kdf"]!!.jsonArray.map { it.jsonObject }) {
            val kdf = StoriiJson.decodeFromJsonElement(Kdf.serializer(), k["kdf"]!!)
            val keys = Crypto.deriveKeys(k.s("password"), kdf)
            assertEquals(k.s("password"), k.s("auth_key"), keys.authKey)
            assertEquals(k.s("wrap_key"), Crypto.b64(keys.wrap))
        }
    }

    @Test fun vaultKey() {
        val vk = v["vault_key"]!!.jsonObject
        val wrap = Crypto.unb64(vk.s("wrap_key"))
        assertEquals(vk.s("wrapped"), Crypto.wrapVaultKey(wrap, Crypto.unb64(vk.s("vault_key")), Crypto.unb64(vk.s("nonce"))))
        assertEquals(vk.s("vault_key"), Crypto.b64(Crypto.unwrapVaultKey(wrap, vk.s("wrapped"))))
        assertThrows(DecryptionException::class.java) { Crypto.unwrapVaultKey(ByteArray(32), vk.s("wrapped")) }
    }

    @Test fun items() {
        for (it in v["items"]!!.jsonArray.map { it.jsonObject }) {
            val key = Crypto.unb64(it.s("vault_key"))
            assertEquals(it.s("data"), Crypto.encryptRaw(key, it.s("id"), it.s("plaintext"), Crypto.unb64(it.s("nonce"))))
            val item = Crypto.decryptItem(key, it.s("id"), it.s("data"))
            val expected = Json.parseToJsonElement(it.s("plaintext")).jsonObject
            assertEquals(expected["name"]!!.jsonPrimitive.content, item.name)
            assertEquals(expected["kind"]!!.jsonPrimitive.content, item.kind)
            // Round trip: what Kotlin writes decodes to the same JSON object.
            val again = Json.parseToJsonElement(StoriiJson.encodeToString(sh.base2.storii.core.Item.serializer(), item)).jsonObject
            assertEquals(expected, again)
            assertThrows(DecryptionException::class.java) { Crypto.decryptItem(key, "00000000-0000-0000-0000-000000000000", it.s("data")) }
        }
    }

    @Test fun totp() {
        for (c in v["totp"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(c.toString(), c.s("code"), Totp.fromFields(c.map("fields")).code(c["time"]!!.jsonPrimitive.long * 1000))
        }
    }

    @Test fun otpauth() {
        for (c in v["otpauth"]!!.jsonArray.map { it.jsonObject }) {
            if (c["error"]?.jsonPrimitive?.boolean == true) {
                assertThrows(c.s("uri"), IllegalArgumentException::class.java) { Totp.parseUri(c.s("uri")) }
            } else {
                assertEquals(c.s("uri"), c.map("fields"), Totp.parseUri(c.s("uri")).fields())
            }
        }
    }

    @Test fun match() {
        for (c in v["match"]!!.jsonArray.map { it.jsonObject }) {
            assertEquals(c.toString(), c["match"]!!.jsonPrimitive.boolean, Match.matchesHost(c.s("context_url"), c.s("host")))
        }
    }
}
