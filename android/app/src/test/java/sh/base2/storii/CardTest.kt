package sh.base2.storii

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test
import sh.base2.storii.core.Card
import java.io.File

/** testdata/cards.json, shared with Go, the extension and iOS. */
class CardTest {
    private val v = Json.parseToJsonElement(File("../../testdata/cards.json").readText()).jsonObject

    @Test
    fun numbers() {
        for (e in v.getValue("numbers").jsonArray) {
            val o = e.jsonObject
            val n = o.getValue("number").jsonPrimitive.content
            assertEquals(n, o.getValue("brand").jsonPrimitive.content, Card.brand(n))
            assertEquals(n, o.getValue("valid").jsonPrimitive.boolean, Card.valid(n))
            assertEquals(n, o.getValue("masked").jsonPrimitive.content, Card.masked(n))
        }
    }

    @Test
    fun expiry() {
        for (e in v.getValue("expiry").jsonArray) {
            val o = e.jsonObject
            val input = o.getValue("input").jsonPrimitive.content
            assertEquals(input, o.getValue("normalized").jsonPrimitive.content, Card.normalizeExpiry(input))
        }
    }
}
