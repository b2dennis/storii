package sh.base2.storii

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import sh.base2.storii.core.BitwardenImport
import sh.base2.storii.core.Item
import sh.base2.storii.core.StoriiJson
import java.io.File

private fun JsonObject.s(k: String) = this[k]?.jsonPrimitive?.content.orEmpty()
private fun item(e: JsonElement) = StoriiJson.decodeFromJsonElement(Item.serializer(), e)

/**
 * Imports [parsed] (a whole-vault export) into the vault of testdata/import/[casesFile] and compares the plan with its
 * lines. internal/importer uses the same files.
 */
fun checkCases(parsed: BitwardenImport.Parsed, casesFile: String) {
    val cases = Json.parseToJsonElement(File("../../testdata/import/$casesFile").readText()).jsonObject
    val privateKey = Json.parseToJsonElement(File("../../testdata/passkey.json").readText())
        .jsonObject["passkey"]!!.jsonObject["private_key"]!!.jsonPrimitive.content
    assertEquals(cases["failed"]!!.jsonArray.map { it.jsonPrimitive.content }, parsed.failed.map { it.substringBefore(" (") })
    val existing = cases["existing"]!!.jsonObject.mapValues { item(it.value) }
    var n = 0
    val plan = BitwardenImport.build(existing, parsed, { "new-${++n}" })
    val want = cases["lines"]!!.jsonArray.map { it.jsonObject }
    assertEquals(want.size, plan.lines.size)
    want.forEachIndexed { i, w ->
        val got = plan.lines[i]
        val line = "line ${i + 1}"
        assertEquals(line, listOf(w.s("action").uppercase(), w.s("id"), w.s("name")), listOf(got.action.name, got.id, got.name))
        if (w.s("action") != "add") return@forEachIndexed
        val it = plan.writes.getValue(got.id!!)
        var fields = it.fields
        if (it.type == Item.PASSKEY) {
            assertEquals(line, privateKey, fields["private_key"])
            fields = fields - "private_key"
        }
        assertEquals(line, w.s("type"), it.type)
        assertEquals(line, w.s("notes"), it.notes.orEmpty())
        assertEquals(line, w["contexts"]?.jsonArray?.map { c -> c.jsonPrimitive.content } ?: emptyList<String>(), it.contexts)
        assertEquals(line, w["fields"]!!.jsonObject.mapValues { f -> f.value.jsonPrimitive.content }, fields)
    }
    val newContexts = cases["new_contexts"]!!.jsonObject
    newContexts.forEach { (id, e) ->
        val w = item(e)
        val c = plan.writes.getValue(id)
        assertEquals(id, listOf(w.name, w.contextType, w.urls), listOf(c.name, c.contextType, c.urls))
    }
    assertEquals(want.count { it.s("action") == "add" } + newContexts.size, plan.writes.size)
    // Importing the same file again changes nothing.
    assertEquals(0, BitwardenImport.build(existing + plan.writes, parsed, { "x" }).writes.size)
}
