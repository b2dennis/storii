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

    @Test
    fun fromForm() {
        assertEquals(mapOf("number" to "5555555555554444", "cardholder" to "New Card", "expiry" to "03/30", "cvc" to "987"),
            Card.fromForm("5555 5555 5555 4444", " New Card ", month = "3", year = "2030", cvc = "987"))
        assertEquals(mapOf("number" to "4242424242424242", "expiry" to "11/31"), Card.fromForm("4242424242424242", expiry = "11 / 31"))
        assertEquals(null, Card.fromForm("4242 4242 4242 4241"))
        assertEquals("Visa 4242", Card.defaultName("4242424242424242"))
        assertEquals("Card 0000", Card.defaultName("0000000000000000"))
    }

    @Test
    fun dropdowns() {
        for ((option, mm) in listOf("01" to "01", "1" to "01", "12 - December" to "12", "Jan" to "01", "März" to "03",
            "juil." to "07", "Mai" to "05", "Month" to "", "13" to "", "Dezember" to "12")) assertEquals(option, mm, Card.monthOf(option))
        for ((option, yy) in listOf("2029" to "29", "29" to "29", "Year" to "", " 2031 " to "31")) assertEquals(option, yy, Card.yearOf(option))
        assertEquals(5, Card.monthOption(listOf("Month", "Jan", "Feb", "Mar", "Apr", "May"), "05"))
        assertEquals(2, Card.yearOption(listOf("YYYY", "2028", "2029"), "29"))
        assertEquals(-1, Card.yearOption(listOf("2028"), "29"))
        assertEquals(-1, Card.monthOption(listOf("01"), ""))
        assertEquals(mapOf("number" to "4242424242424242", "expiry" to "05/29"),
            Card.fromForm("4242 4242 4242 4242", month = Card.monthOf("May"), year = Card.yearOf("2029")))
    }
}
