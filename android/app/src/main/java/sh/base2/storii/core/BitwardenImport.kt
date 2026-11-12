package sh.base2.storii.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import java.util.Base64

/**
 * Bitwarden's JSON export (not the encrypted one): logins with their 2FA codes and passkeys, and cards. Matches
 * internal/importer/bitwarden.go and its shared cases in testdata/import/bitwarden*.json.
 */
object BitwardenImport {
    data class CardRow(val name: String, val cardholder: String, val number: String, val expiry: String, val cvc: String, val note: String)
    data class PasskeyRow(val name: String, val fields: Map<String, String>)
    data class NoteRow(val name: String, val text: String)

    data class Parsed(
        val logins: List<Import.Row>,
        val codes: List<OtpImport.Row>,
        val cards: List<CardRow>,
        val passkeys: List<PasskeyRow>,
        /** Entries storii couldn't read, with the reason in brackets. */
        val failed: List<String>,
        /** Secure notes (only from a credential transfer so far). */
        val notes: List<NoteRow> = emptyList(),
    ) {
        val count get() = logins.size + codes.size + cards.size + passkeys.size + notes.size
    }

    class Encrypted : Exception("This Bitwarden export is encrypted. Export again with the file format \".json\", not \".json (Encrypted)\".")

    private fun root(text: String): JsonObject? =
        runCatching { Json.parseToJsonElement(text.removePrefix("\uFEFF")) as? JsonObject }.getOrNull()
            ?.takeIf { (it["encrypted"] as? JsonPrimitive)?.booleanOrNull != null }

    fun detect(text: String) = text.trimStart().startsWith("{") && root(text) != null

    private fun JsonElement?.obj() = this as? JsonObject
    private fun JsonObject.s(k: String) = (this[k] as? JsonPrimitive)?.takeIf { it.isString || it.content != "null" }?.content.orEmpty()

    fun parse(text: String): Parsed {
        val root = root(text) ?: throw Import.NotAnExport("This isn't a Bitwarden JSON export.")
        if ((root["encrypted"] as JsonPrimitive).booleanOrNull == true) throw Encrypted()
        val logins = mutableListOf<Import.Row>()
        val codes = mutableListOf<OtpImport.Row>()
        val cards = mutableListOf<CardRow>()
        val passkeys = mutableListOf<PasskeyRow>()
        val failed = mutableListOf<String>()
        for (e in root["items"] as? JsonArray ?: JsonArray(emptyList())) {
            val it = e.obj() ?: continue
            val name = it.s("name")
            val type = it.s("type")
            val login = it["login"].obj()
            val card = it["card"].obj()
            if (type == "1" && login != null) {
                val url = (login["uris"] as? JsonArray)?.firstOrNull()?.obj()?.s("uri")?.trim().orEmpty()
                val password = login.s("password")
                if (password.isNotEmpty()) logins += Import.Row(name.trim(), url, login.s("username").trim(), password, it.s("notes").trim())
                val code = login.s("totp").trim()
                if (code.isNotEmpty()) {
                    runCatching { totp(code, name, login.s("username")) }
                        .onSuccess { t -> codes += OtpImport.Row(t.issuer.ifEmpty { name.ifEmpty { t.account.ifEmpty { "2FA code" } } }, t) }
                        .onFailure { e -> failed += "$name (2FA code: ${e.message})" }
                }
                for (f in login["fido2Credentials"] as? JsonArray ?: JsonArray(emptyList())) {
                    val c = f.obj() ?: continue
                    runCatching {
                        require(c.s("rpId").isNotEmpty()) { "no website" }
                        passkey(c.s("credentialId"), c.s("keyAlgorithm"), c.s("keyCurve"), c.s("keyValue"), c.s("userHandle")) +
                            mapOf("rp_id" to c.s("rpId").lowercase(), "user_name" to c.s("userName"), "user_display_name" to c.s("userDisplayName"))
                    }.onSuccess { fields -> passkeys += PasskeyRow(c.s("rpName").ifEmpty { c.s("rpId") }, fields) }
                        .onFailure { e -> failed += "$name (passkey: ${e.message})" }
                }
            } else if (type == "3" && card != null) {
                val m = card.s("expMonth")
                val y = card.s("expYear")
                cards += CardRow(name.trim(), card.s("cardholderName").trim(), Card.digits(card.s("number")),
                    if (m.isNotEmpty() && y.isNotEmpty()) Card.normalizeExpiry("$m/$y") else "", card.s("code").trim(), it.s("notes").trim())
            }
        }
        return Parsed(logins, codes, cards, passkeys, failed)
    }

    /** A login's 2FA field: an otpauth:// URI or a bare base32 secret (Steam codes aren't supported). */
    internal fun totp(code: String, name: String, user: String): Totp = when {
        code.startsWith("otpauth://", ignoreCase = true) -> Totp.parseUri(code)
        "://" in code -> throw IllegalArgumentException("unsupported kind")
        else -> Totp.fromFields(mapOf("secret" to code, "issuer" to name, "account" to user))
    }

    private val guid = Regex("^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$")

    /** Credential ids are GUIDs (16 bytes) or "b64."-prefixed base64url; the key is PKCS#8 in base64url. */
    internal fun passkey(credId: String, alg: String, curve: String, key: String, userHandle: String): Map<String, String> {
        require(alg.equals("ECDSA", true) && curve.equals("P-256", true)) { "unsupported key type $alg $curve" }
        val id = runCatching {
            when {
                credId.startsWith("b64.") -> unb64(credId.substring(4))
                guid.matches(credId) -> credId.replace("-", "").chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                else -> unb64(credId)
            }
        }.getOrNull()?.takeIf { it.isNotEmpty() } ?: throw IllegalArgumentException("unreadable credential id")
        val der = runCatching { unb64(key) }.getOrNull() ?: throw IllegalArgumentException("unreadable key")
        val p256 = runCatching {
            val info = PrivateKeyInfo.getInstance(der)
            info.privateKeyAlgorithm.parameters == X9ObjectIdentifiers.prime256v1
        }.getOrDefault(false)
        require(p256) { "unreadable key" }
        return buildMap {
            put("credential_id", Passkey.b64u(id))
            put("private_key", Passkey.b64u(der))
            if (userHandle.isNotEmpty()) put("user_handle", Passkey.b64u(runCatching { unb64(userHandle) }.getOrNull()
                ?: throw IllegalArgumentException("unreadable user handle")))
        }
    }

    /** base64url or standard base64, padded or not. */
    private fun unb64(s: String): ByteArray = Base64.getUrlDecoder().decode(s.trim().replace('+', '-').replace('/', '_').trimEnd('='))

    /**
     * Matches everything against the vault: logins (as [Import.build]), 2FA codes (as [OtpImport.build]), then cards
     * (skipped when a card with the same number exists), passkeys (skipped when the credential id exists) and notes
     * (skipped when a note with the same name and text exists).
     */
    fun build(existing: Map<String, Item>, p: Parsed, newId: () -> String, now: String = Item.now()): Import.Plan {
        val items = existing.toMutableMap()
        val writes = linkedMapOf<String, Item>()
        val lines = mutableListOf<Import.Line>()
        fun merge(plan: Import.Plan) { items += plan.writes; writes += plan.writes; lines += plan.lines }
        fun put(id: String, it: Item) { items[id] = it; writes[id] = it }
        merge(Import.build(items, p.logins, newId, now))
        merge(OtpImport.build(items, p.codes, newId, now))

        for (c in p.cards) {
            val name = c.name.ifEmpty { "${Card.displayBrand(c.number).ifEmpty { "Card" }} ${c.number.takeLast(4)}".trim() }
            if (c.number.isEmpty()) { lines += Import.Line(Import.Action.INVALID, name = name); continue }
            val dup = items.keys.sorted().firstOrNull { id ->
                val it = items.getValue(id)
                it.isSecret && it.type == Item.CARD && Card.digits(it.field("number")) == c.number
            }
            if (dup != null) { lines += Import.Line(Import.Action.SKIP, dup, name, Card.masked(c.number)); continue }
            val fields = buildMap {
                put("number", c.number)
                if (c.cardholder.isNotEmpty()) put("cardholder", c.cardholder)
                if (c.expiry.isNotEmpty()) put("expiry", c.expiry)
                if (c.cvc.isNotEmpty()) put("cvc", c.cvc)
            }
            val id = newId()
            put(id, Item(kind = Item.KIND_SECRET, type = Item.CARD, name = name, fields = fields, notes = c.note.ifEmpty { null },
                createdAt = now, updatedAt = now))
            lines += Import.Line(Import.Action.ADD, id, name, Card.masked(c.number))
        }

        for (pk in p.passkeys) {
            val rp = pk.fields.getValue("rp_id")
            val dup = items.keys.sorted().firstOrNull { id ->
                val it = items.getValue(id)
                it.isSecret && it.type == Item.PASSKEY && it.field("credential_id") == pk.fields["credential_id"]
            }
            if (dup != null) { lines += Import.Line(Import.Action.SKIP, dup, pk.name, rp); continue }
            val ctx = items.keys.sorted().firstOrNull { id ->
                val c = items.getValue(id)
                c.isContext && c.urls.any { Match.host(it) == rp }
            } ?: newId().also { id ->
                put(id, Item(kind = Item.KIND_CONTEXT, name = rp, contextType = "website", urls = listOf("https://$rp"), createdAt = now, updatedAt = now))
            }
            val id = newId()
            put(id, Item(kind = Item.KIND_SECRET, type = Item.PASSKEY, name = pk.name, contexts = listOf(ctx), fields = pk.fields,
                createdAt = now, updatedAt = now))
            lines += Import.Line(Import.Action.ADD, id, pk.name, rp)
        }

        for (n in p.notes) {
            val dup = items.keys.sorted().firstOrNull { id ->
                val it = items.getValue(id)
                it.isSecret && it.type == Item.NOTE && it.name == n.name && it.notes.orEmpty() == n.text
            }
            if (dup != null) { lines += Import.Line(Import.Action.SKIP, dup, n.name); continue }
            val id = newId()
            put(id, Item(kind = Item.KIND_SECRET, type = Item.NOTE, name = n.name, notes = n.text, createdAt = now, updatedAt = now))
            lines += Import.Line(Import.Action.ADD, id, n.name)
        }
        return Import.Plan(writes, lines)
    }
}
