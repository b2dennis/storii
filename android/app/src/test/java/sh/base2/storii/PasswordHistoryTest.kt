package sh.base2.storii

import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test
import sh.base2.storii.core.HistoryEntry
import sh.base2.storii.core.Item
import sh.base2.storii.core.PasswordHistory
import sh.base2.storii.core.StoriiJson
import java.io.File

/** testdata/history.json, shared with Go, the extension and iOS. */
class PasswordHistoryTest {
    @Test
    fun cases() {
        val v = StoriiJson.parseToJsonElement(File("../../testdata/history.json").readText()).jsonObject
        val now = v.getValue("now").jsonPrimitive.content
        for (e in v.getValue("cases").jsonArray) {
            val c = e.jsonObject
            fun item(k: String) = StoriiJson.decodeFromJsonElement(Item.serializer(), c.getValue(k).jsonObject.let {
                kotlinx.serialization.json.JsonObject(it + ("name" to kotlinx.serialization.json.JsonPrimitive("x")))
            })
            val want = c["want"]?.jsonArray?.map { StoriiJson.decodeFromJsonElement(HistoryEntry.serializer(), it) }.orEmpty()
            assertEquals(c.getValue("name").jsonPrimitive.content, want, PasswordHistory.apply(item("prev"), item("next"), now).history)
        }
    }
}
