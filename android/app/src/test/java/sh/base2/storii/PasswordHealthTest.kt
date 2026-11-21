package sh.base2.storii

import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test
import sh.base2.storii.core.Item
import sh.base2.storii.core.PasswordHealth
import sh.base2.storii.core.StoriiJson
import java.io.File

/** testdata/health.json, shared with Go, the extension and iOS. */
class PasswordHealthTest {
    private val v = StoriiJson.parseToJsonElement(File("../../testdata/health.json").readText()).jsonObject

    @Test
    fun weak() {
        for (e in v.getValue("weak").jsonArray) {
            val pw = e.jsonObject.getValue("password").jsonPrimitive.content
            assertEquals(pw, e.jsonObject.getValue("weak").jsonPrimitive.boolean, PasswordHealth.weak(pw))
        }
    }

    @Test
    fun check() {
        val items = v.getValue("items").jsonObject.mapValues { StoriiJson.decodeFromJsonElement(Item.serializer(), it.value) }
        val want = v.getValue("health").jsonObject
        val got = PasswordHealth.check(items)
        assertEquals(want.getValue("weak").jsonArray.map { it.jsonPrimitive.content }, got.weak)
        assertEquals(want.getValue("reused").jsonArray.map { g -> g.jsonArray.map { it.jsonPrimitive.content } }, got.reused)
    }

    @Test
    fun pwned() {
        val p = v.getValue("pwned").jsonObject
        fun s(k: String) = p.getValue(k).jsonPrimitive.content
        assertEquals(s("prefix") to s("suffix"), PasswordHealth.pwnedHash(s("password")))
        assertEquals(p.getValue("count").jsonPrimitive.int, PasswordHealth.pwnedCount(s("body"), s("suffix")))
        assertEquals(0, PasswordHealth.pwnedCount(s("body"), s("missing_suffix")))
        assertEquals(0, PasswordHealth.pwnedCount(s("body"), s("padding_suffix")))
    }
}
