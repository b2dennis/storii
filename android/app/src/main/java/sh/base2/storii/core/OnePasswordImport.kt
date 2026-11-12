package sh.base2.storii.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.ZipInputStream

/**
 * 1Password's .1pux export (a zip holding export.data), or export.data on its own: logins with their 2FA codes,
 * passwords, and cards. 1Password leaves passkeys out; archived items are skipped. Matches
 * internal/importer/onepassword.go and its shared cases in testdata/import/1password*.json.
 */
object OnePasswordImport {
    private fun root(text: String): JsonObject? =
        runCatching { Json.parseToJsonElement(text.removePrefix("﻿")) as? JsonObject }.getOrNull()
            ?.takeIf { ((it["accounts"] as? JsonArray)?.firstOrNull() as? JsonObject)?.get("vaults") is JsonArray }

    fun detect(text: String) = text.trimStart().startsWith("{") && root(text) != null

    /** export.data from a .1pux zip (attachments are skipped without being read into memory), or null. */
    fun unzip(input: InputStream, maxBytes: Int): String? {
        ZipInputStream(input).use { z ->
            while (true) {
                val e = z.nextEntry ?: return null
                if (e.name != "export.data") continue
                val out = ByteArrayOutputStream()
                val buf = ByteArray(64 shl 10)
                while (true) {
                    val n = z.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > maxBytes) error("That file is too big for a password export.")
                }
                return out.toString(Charsets.UTF_8.name())
            }
        }
    }

    private fun JsonElement?.obj() = this as? JsonObject
    private fun JsonElement?.arr() = this as? JsonArray ?: JsonArray(emptyList())
    private fun JsonObject.s(k: String) = (this[k] as? JsonPrimitive)?.takeIf { it.isString || it.content != "null" }?.content?.trim().orEmpty()

    fun parse(text: String): BitwardenImport.Parsed {
        val root = root(text) ?: throw Import.NotAnExport("This isn't a 1Password export (.1pux).")
        val logins = mutableListOf<Import.Row>()
        val codes = mutableListOf<OtpImport.Row>()
        val cards = mutableListOf<BitwardenImport.CardRow>()
        val failed = mutableListOf<String>()
        val items = root["accounts"].arr().flatMap { a -> a.obj()?.get("vaults").arr() ?: emptyList() }
            .flatMap { v -> v.obj()?.get("items").arr() ?: emptyList() }.mapNotNull { it.obj() }
        for (it in items) {
            if (it.s("state") == "archived") continue
            val overview = it["overview"].obj() ?: JsonObject(emptyMap())
            val details = it["details"].obj() ?: JsonObject(emptyMap())
            val name = overview.s("title")
            val note = details.s("notesPlain")
            val url = overview.s("url").ifEmpty { overview["urls"].arr().firstOrNull()?.obj()?.s("url").orEmpty() }
            val fields = details["sections"].arr().flatMap { s -> s.obj()?.get("fields").arr() ?: emptyList() }.mapNotNull { f -> f.obj() }
            fun value(id: String) = fields.firstOrNull { f -> f.s("id") == id }?.get("value").obj()
            when (it.s("categoryUuid")) {
                "001", "005" -> {
                    var user = ""
                    var pw = details["password"]?.let { p -> (p as? JsonPrimitive)?.content }.orEmpty()
                    for (f in details["loginFields"].arr().mapNotNull { f -> f.obj() }) {
                        val v = (f["value"] as? JsonPrimitive)?.content.orEmpty()
                        when (f.s("designation")) {
                            "username" -> user = v.trim()
                            "password" -> pw = v
                        }
                    }
                    if (pw.isNotEmpty()) logins += Import.Row(name, url, user, pw, note)
                    for (f in fields) {
                        val code = f["value"].obj()?.s("totp").orEmpty()
                        if (code.isEmpty()) continue
                        runCatching { BitwardenImport.totp(code, name, user) }
                            .onSuccess { t -> codes += OtpImport.Row(t.issuer.ifEmpty { name.ifEmpty { t.account.ifEmpty { "2FA code" } } }, t) }
                            .onFailure { e -> failed += "$name (2FA code: ${e.message})" }
                    }
                }
                "002" -> {
                    // monthYear is YYYYMM, e.g. 202703.
                    val my = value("expiry")?.s("monthYear").orEmpty()
                    val expiry = if (my.length == 6) Card.normalizeExpiry("${my.substring(4)}/${my.substring(2, 4)}") else ""
                    val cvc = value("cvv")?.let { v -> v.s("concealed").ifEmpty { v.s("string") } }.orEmpty()
                    cards += BitwardenImport.CardRow(name, value("cardholder")?.s("string").orEmpty(),
                        Card.digits(value("ccnum")?.s("creditCardNumber").orEmpty()), expiry, cvc, note)
                }
            }
        }
        return BitwardenImport.Parsed(logins, codes, cards, emptyList(), failed)
    }
}
