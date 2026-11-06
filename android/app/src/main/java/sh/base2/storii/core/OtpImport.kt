package sh.base2.storii.core

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * 2FA secrets from other apps: Authy token exports (decrypted with the Authy backup password), the same tokens already
 * decrypted by another tool, or lists of otpauth:// URIs. Matches internal/importer/otp.go and its shared cases in
 * testdata/import/authy*.json.
 */
object OtpImport {
    enum class Kind { LOGINS, AUTHY, OTP }

    data class Row(val name: String, val totp: Totp)

    class NeedPassword : Exception("This Authy export is encrypted with your Authy backup password.")
    class WrongPassword : Exception("None of the codes could be decrypted. Is that your Authy backup password?")
    class Empty : Exception("No 2FA codes found in this file.")

    data class Parsed(val rows: List<Row>, val failed: List<String>)

    fun detect(text: String): Kind {
        val s = text.removePrefix("\uFEFF")
        return when {
            "encrypted_seed" in s -> Kind.AUTHY
            "decrypted_seed" in s || s.contains("otpauth://totp/", ignoreCase = true) -> Kind.OTP
            else -> Kind.LOGINS
        }
    }

    fun parse(text: String, authyPassword: String?): Parsed {
        val s = text.removePrefix("\uFEFF")
        val kind = detect(s)
        if (kind == Kind.AUTHY && authyPassword.isNullOrEmpty()) throw NeedPassword()
        val tokens = authyTokens(s)
        val rows = mutableListOf<Row>()
        val failed = mutableListOf<String>()
        if (tokens.isEmpty()) {
            for (f in s.split(Regex("[\\s\",'<>\\[\\]]+"))) {
                if (!f.startsWith("otpauth://", ignoreCase = true)) continue
                runCatching { Totp.parseUri(f) }
                    .onSuccess { rows.add(Row(name(it, ""), it)) }
                    .onFailure { e -> failed.add("${f.substringBefore('?')}: ${e.message}") }
            }
            if (rows.isEmpty() && failed.isEmpty()) throw Empty()
            return Parsed(rows, failed)
        }
        var decrypted = 0
        for (tok in tokens) {
            val label = listOf("name", "original_name", "issuer").firstNotNullOfOrNull { tok[it]?.trim()?.ifEmpty { null } } ?: "a token without a name"
            val encrypted = tok["decrypted_seed"].isNullOrEmpty()
            val seed = if (encrypted) runCatching { decrypt(tok, authyPassword!!) }.getOrNull() else tok["decrypted_seed"]
            val secret = seed?.let { seedBytes(it) }
            if (secret == null) {
                failed.add(label)
                continue
            }
            if (encrypted) decrypted++
            var issuer = tok["issuer"].orEmpty().trim()
            var account = ""
            val name = tok["name"].orEmpty().trim()
            if (':' in name) {
                if (issuer.isEmpty()) issuer = name.substringBefore(':').trim()
                account = name.substringAfter(':').trim()
            } else if (!name.equals(issuer, ignoreCase = true)) account = name
            val digits = tok["digits"]?.toDoubleOrNull()?.toInt()?.takeIf { it in 6..10 } ?: 6
            val t = Totp(secret, digits = digits, issuer = issuer, account = account)
            rows.add(Row(name(t, name), t))
        }
        if (kind == Kind.AUTHY && decrypted == 0 && failed.isNotEmpty()) throw WrongPassword()
        return Parsed(rows, failed)
    }

    /** Token objects (anything with encrypted_seed or decrypted_seed) in JSON of any shape, or a CSV with those columns. */
    private fun authyTokens(text: String): List<Map<String, String>> {
        val tokens = mutableListOf<Map<String, String>>()
        fun walk(e: JsonElement) {
            when (e) {
                is JsonArray -> e.forEach(::walk)
                is JsonObject -> if ("encrypted_seed" in e || "decrypted_seed" in e) {
                    tokens.add(e.mapNotNull { (k, v) -> (v as? JsonPrimitive)?.takeIf { it.isString || it.content.toDoubleOrNull() != null }?.let { k to it.content } }.toMap())
                } else e.values.forEach(::walk)
                else -> {}
            }
        }
        val json = runCatching { Json.parseToJsonElement(text) }.getOrNull()
        if (json != null) {
            walk(json)
            return tokens
        }
        val records = Import.csv(text)
        val header = records.firstOrNull()?.map { it.trim() } ?: return emptyList()
        if ("encrypted_seed" !in header && "decrypted_seed" !in header) return emptyList()
        return records.drop(1).map { r -> header.indices.filter { it < r.size }.associate { header[it] to r[it] } }
    }

    /** AES-256-CBC, key = PBKDF2-HMAC-SHA1(backup password, salt as text, key_derivation_iterations or 1000), IV = hex unique_iv or zeros. */
    private fun decrypt(tok: Map<String, String>, password: String): String? {
        val ct = runCatching { Base64.getDecoder().decode(tok["encrypted_seed"].orEmpty().trim()) }.getOrNull() ?: return null
        if (ct.isEmpty() || ct.size % 16 != 0) return null
        val rounds = tok["key_derivation_iterations"]?.toDoubleOrNull()?.toInt()?.takeIf { it > 0 } ?: 1000
        val gen = PKCS5S2ParametersGenerator(SHA1Digest())
        gen.init(password.toByteArray(Charsets.UTF_8), tok["salt"].orEmpty().toByteArray(Charsets.UTF_8), rounds)
        val key = (gen.generateDerivedParameters(256) as KeyParameter).key
        val ivHex = tok["unique_iv"].orEmpty().trim()
        val iv = if (ivHex.isEmpty()) ByteArray(16) else hex(ivHex)?.takeIf { it.size == 16 } ?: return null
        val pt = Cipher.getInstance("AES/CBC/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            doFinal(ct)
        }
        val n = pt.last().toInt() and 0xff
        if (n == 0 || n > 16 || (pt.size - n until pt.size).any { (pt[it].toInt() and 0xff) != n }) return null
        return String(pt, 0, pt.size - n, Charsets.UTF_8)
    }

    private fun seedBytes(seed: String): ByteArray? {
        val s = seed.trim()
        runCatching { Base32.decode(s) }.getOrNull()?.takeIf { it.isNotEmpty() }?.let { return it }
        return hex(s)?.takeIf { it.isNotEmpty() }
    }

    private fun hex(s: String): ByteArray? {
        if (s.length % 2 != 0 || s.any { it.lowercaseChar() !in "0123456789abcdef" }) return null
        return ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    private fun name(t: Totp, fallback: String) = t.issuer.ifEmpty { fallback.ifEmpty { t.account.ifEmpty { "2FA code" } } }

    /** Matches codes against the vault: a secret already saved is skipped, the others are linked to a fitting context. */
    fun build(existing: Map<String, Item>, rows: List<Row>, newId: () -> String, now: String = Item.now()): Import.Plan {
        val items = existing.toMutableMap()
        val writes = linkedMapOf<String, Item>()
        val lines = rows.map { r ->
            val secret = r.totp.fields().getValue("secret")
            val dup = items.keys.sorted().firstOrNull { id ->
                val it = items.getValue(id)
                it.isSecret && it.type == Item.TOTP && runCatching { Totp.fromFields(it.fields).fields()["secret"] }.getOrNull() == secret
            }
            if (dup != null) return@map Import.Line(Import.Action.SKIP, dup, r.name, r.totp.account)
            val ctx = contextFor(items, listOf(r.totp.issuer, r.name))
            val item = Item(kind = Item.KIND_SECRET, type = Item.TOTP, name = r.name, fields = r.totp.fields(),
                contexts = listOfNotNull(ctx), createdAt = now, updatedAt = now)
            val id = newId()
            items[id] = item
            writes[id] = item
            Import.Line(Import.Action.ADD, id, r.name, r.totp.account)
        }
        return Import.Plan(writes, lines)
    }

    private fun contextFor(items: Map<String, Item>, names: List<String>): String? {
        fun norm(s: String) = s.lowercase().filter { it in 'a'..'z' || it in '0'..'9' }
        for (n in names) {
            val want = norm(n)
            if (want.isEmpty()) continue
            items.keys.sorted().firstOrNull { id ->
                val c = items.getValue(id)
                c.isContext && (norm(c.name) == want || c.urls.any { norm(Match.host(it).substringBefore('.')) == want })
            }?.let { return it }
        }
        return null
    }
}
