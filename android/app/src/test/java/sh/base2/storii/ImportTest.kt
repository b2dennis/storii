package sh.base2.storii

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.base2.storii.core.Import
import sh.base2.storii.core.OtpImport
import sh.base2.storii.core.Item
import sh.base2.storii.core.StoriiJson
import java.io.File

/** testdata/import, shared with the Go importer (internal/importer). */
class ImportTest {
    private val cases = Json.parseToJsonElement(File("../../testdata/import/cases.json").readText()).jsonObject
    private val rows = Import.parse(File("../../testdata/import/google.csv").readText())
    private fun JsonObject.s(k: String) = this[k]?.jsonPrimitive?.content.orEmpty()

    @Test fun sharedCases() {
        val existing = cases["existing"]!!.jsonObject.mapValues { StoriiJson.decodeFromJsonElement(Item.serializer(), it.value) }
        val want = cases["rows"]!!.jsonArray.map { it.jsonObject }
        assertEquals(want.size, rows.size)
        var n = 0
        val plan = Import.build(existing, rows, { "new-${++n}" })
        want.forEachIndexed { i, w ->
            val got = plan.lines[i]
            val row = "row ${i + 1}"
            assertEquals(row, w.s("action").uppercase(), got.action.name)
            when (got.action) {
                Import.Action.USERNAME -> {
                    assertEquals(row, w.s("id"), got.id)
                    assertEquals(row, w.s("username"), plan.writes.getValue(got.id!!).field("username"))
                }
                Import.Action.ADD -> {
                    val it = plan.writes.getValue(got.id!!)
                    assertEquals(row, w.s("name"), it.name)
                    assertEquals(row, w.s("username"), it.field("username"))
                    assertEquals(row, w.s("password"), it.field("password"))
                    assertEquals(row, w.s("notes"), it.notes.orEmpty())
                    assertEquals(row, w["differs"]?.jsonPrimitive?.boolean ?: false, got.differs)
                    when {
                        w.containsKey("context") -> assertEquals(row, listOf(w.s("context")), it.contexts)
                        w.containsKey("new_context") -> {
                            val c = plan.writes.getValue(it.contexts.single())
                            val wc = StoriiJson.decodeFromJsonElement(Item.serializer(), w["new_context"]!!.let {
                                JsonObject(it.jsonObject + ("kind" to kotlinx.serialization.json.JsonPrimitive("context")))
                            })
                            assertEquals(row, listOf(wc.name, wc.contextType, wc.urls, wc.androidPackages), listOf(c.name, c.contextType, c.urls, c.androidPackages))
                        }
                        else -> assertTrue(row, it.contexts.isEmpty())
                    }
                }
                else -> {}
            }
        }
        // Importing again changes nothing.
        val again = Import.build(existing + plan.writes, rows, { "again-${++n}" })
        assertTrue(again.lines.toString(), again.writes.isEmpty())
    }

    @Test fun otherExports() {
        for (csv in listOf(
            "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\"\n\"https://github.com\",\"dennis\",\"pw\",,\"https://github.com\",\"{x}\"\n",
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,GitHub,,,0,https://github.com,dennis,pw,\n",
            "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nGitHub,https://github.com,dennis,pw,,false,false,,\n",
        )) {
            val r = Import.parse("\uFEFF" + csv).single()
            assertEquals(listOf("https://github.com", "dennis", "pw"), listOf(r.url, r.username, r.password))
        }
        assertThrows(Import.NotAnExport::class.java) { Import.parse("a,b\n1,2\n") }
    }
}

/** testdata/import/authy*.json, shared with internal/importer/otp_test.go. */
class OtpImportTest {
    private val data = File("../../testdata/import/authy.json").readText()
    private val cases = Json.parseToJsonElement(File("../../testdata/import/authy-cases.json").readText()).jsonObject
    private val password = cases["password"]!!.jsonPrimitive.content

    @Test fun authy() {
        assertEquals(OtpImport.Kind.AUTHY, OtpImport.detect(data))
        assertThrows(OtpImport.NeedPassword::class.java) { OtpImport.parse(data, null) }
        assertThrows(OtpImport.WrongPassword::class.java) { OtpImport.parse(data, "wrong") }
        val parsed = OtpImport.parse(data, password)
        val want = cases["tokens"]!!.jsonArray.map { it.jsonObject }
        assertEquals(emptyList<String>(), parsed.failed)
        assertEquals(want.size, parsed.rows.size)
        want.forEachIndexed { i, w ->
            val r = parsed.rows[i]
            fun s(k: String) = w[k]!!.jsonPrimitive.content
            assertEquals("token $i", listOf(s("name"), s("issuer"), s("account"), s("secret"), s("digits")),
                listOf(r.name, r.totp.issuer, r.totp.account, r.totp.fields()["secret"], r.totp.digits.toString()))
        }
        val existing = mapOf("ctx-gh" to Item(kind = Item.KIND_CONTEXT, name = "github.com", contextType = "website", urls = listOf("https://github.com")))
        var n = 0
        val plan = OtpImport.build(existing, parsed.rows, { "new-${++n}" })
        want.forEachIndexed { i, w ->
            val l = plan.lines[i]
            val dup = w["duplicate_of"]?.jsonPrimitive?.content?.toInt()
            if (dup != null) {
                assertEquals("token $i", Import.Action.SKIP, l.action)
                assertEquals("token $i", plan.lines[dup].id, l.id)
            } else {
                assertEquals("token $i", Import.Action.ADD, l.action)
                assertEquals("token $i", listOfNotNull(w["context"]?.jsonPrimitive?.content), plan.writes.getValue(l.id!!).contexts)
            }
        }
        assertEquals(0, OtpImport.build(existing + plan.writes, parsed.rows, { "x" }).count(Import.Action.ADD))
    }

    @Test fun otpauthList() {
        val text = "otpauth://totp/GitHub:dennis?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n  otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQ&digits=8\nnot a uri\notpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1\n"
        assertEquals(OtpImport.Kind.OTP, OtpImport.detect(text))
        val p = OtpImport.parse(text, null)
        assertEquals(listOf("GitHub", "Example"), p.rows.map { it.name })
        assertEquals(listOf("dennis", 8), listOf(p.rows[0].totp.account, p.rows[1].totp.digits))
        assertEquals(1, p.failed.size)
        assertEquals(OtpImport.Kind.LOGINS, OtpImport.detect("name,url,username,password,note\n"))
    }
}
