package sh.base2.storii.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The FIDO Credential Exchange Format (CXF 1.0), what Android's credential transfer hands over when the user moves
 * their passwords and passkeys from another app (Google Password Manager, for one) to storii: logins, passkeys, 2FA
 * codes, cards and notes. Shared cases in testdata/import/cxf*.json.
 */
object CxfImport {
    private fun JsonElement?.obj() = this as? JsonObject
    private fun JsonElement?.arr() = this as? JsonArray ?: JsonArray(emptyList())
    private fun JsonObject.s(k: String) = (this[k] as? JsonPrimitive)?.takeIf { it.isString || it.content != "null" }?.content.orEmpty()
    /** An EditableField's value ({"fieldType": ..., "value": ...}). */
    private fun JsonObject.field(k: String) = this[k].obj()?.s("value").orEmpty()

    /**
     * The CXF header (version, exporter, accounts). Android hands it over as is; a CXP-style envelope with the header
     * in "payload" (as an object, JSON text or base64url JSON) is unwrapped too, in case an exporter sends one.
     */
    internal fun header(text: String, depth: Int = 0): JsonObject? {
        val root = runCatching { Json.parseToJsonElement(text.removePrefix("\uFEFF")) as? JsonObject }.getOrNull() ?: return null
        if (root["accounts"] is JsonArray) return root
        if (depth > 0) return null
        return when (val p = root["payload"]) {
            is JsonObject -> p.takeIf { it["accounts"] is JsonArray }
            is JsonPrimitive -> header(p.content, 1) ?: runCatching {
                String(java.util.Base64.getUrlDecoder().decode(p.content.trim().replace('+', '-').replace('/', '_').trimEnd('=')))
            }.getOrNull()?.let { header(it, 1) }
            else -> null
        }
    }

    fun parse(text: String): BitwardenImport.Parsed {
        val root = header(text) ?: throw Import.NotAnExport("The other app sent something storii can't read.")
        val logins = mutableListOf<Import.Row>()
        val codes = mutableListOf<OtpImport.Row>()
        val cards = mutableListOf<BitwardenImport.CardRow>()
        val passkeys = mutableListOf<BitwardenImport.PasskeyRow>()
        val notes = mutableListOf<BitwardenImport.NoteRow>()
        val failed = mutableListOf<String>()
        val items = root["accounts"].arr().flatMap { a -> a.obj()?.get("items").arr() ?: emptyList() }.mapNotNull { it.obj() }
        for (item in items) {
            val title = item.s("title").trim()
            val scope = item["scope"].obj()
            val url = scope?.get("urls").arr().firstOrNull()?.let { (it as? JsonPrimitive)?.content }?.trim()
                ?: scope?.get("androidApps").arr().firstOrNull()?.obj()?.s("bundleId")?.takeIf { it.isNotEmpty() }?.let { "android://$it" }
                ?: ""
            val creds = item["credentials"].arr().mapNotNull { it.obj() }
            val note = creds.filter { it.s("type") == "note" }.map { it.field("content").trim() }.filter { it.isNotEmpty() }.joinToString("\n\n")
            val auth = creds.firstOrNull { it.s("type") == "basic-auth" }
            val user = auth?.field("username")?.trim().orEmpty()
            var used = false
            for (c in creds) when (c.s("type")) {
                "basic-auth" -> {
                    val pw = c.field("password")
                    if (pw.isNotEmpty()) { logins += Import.Row(title, url, c.field("username").trim(), pw, note); used = true }
                }
                "passkey" -> runCatching {
                    val rp = c.s("rpId").trim().lowercase()
                    require(rp.isNotEmpty()) { "no website" }
                    // CXF keys are PKCS#8; passkey() checks that it's a P-256 key.
                    BitwardenImport.passkey(c.s("credentialId"), "ECDSA", "P-256", c.s("key"), c.s("userHandle")) +
                        mapOf("rp_id" to rp, "user_name" to c.s("username"), "user_display_name" to c.s("userDisplayName"))
                }.onSuccess { f -> passkeys += BitwardenImport.PasskeyRow(title.ifEmpty { f.getValue("rp_id") }, f) }
                    .onFailure { e -> failed += "${title.ifEmpty { c.s("rpId") }} (passkey: ${e.message})" }
                "totp" -> runCatching {
                    Totp.fromFields(mapOf("secret" to c.s("secret"), "algorithm" to c.s("algorithm"), "digits" to c.s("digits"),
                        "period" to c.s("period"), "issuer" to c.s("issuer").ifEmpty { title }, "account" to c.s("username").ifEmpty { user }))
                }.onSuccess { t -> codes += OtpImport.Row(t.issuer.ifEmpty { t.account.ifEmpty { "2FA code" } }, t) }
                    .onFailure { e -> failed += "$title (2FA code: ${e.message})" }
                "credit-card" -> {
                    // expiryDate is YYYY-MM.
                    val exp = c.field("expiryDate").trim()
                    val expiry = if (Regex("""\d{4}-\d{2}""").matches(exp)) Card.normalizeExpiry("${exp.substring(5)}/${exp.substring(0, 4)}") else ""
                    cards += BitwardenImport.CardRow(title, c.field("fullName").trim(), Card.digits(c.field("number")), expiry,
                        c.field("verificationNumber").trim(), note)
                    used = true
                }
            }
            // A note on its own (not attached to a login or card) becomes a note in storii.
            if (!used && note.isNotEmpty()) notes += BitwardenImport.NoteRow(title.ifEmpty { "Note" }, note)
        }
        return BitwardenImport.Parsed(logins, codes, cards, passkeys, failed, notes)
    }
}
