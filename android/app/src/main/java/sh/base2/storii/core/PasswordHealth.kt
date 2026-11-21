package sh.base2.storii.core

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.isSuccess
import java.security.MessageDigest
import kotlin.math.ln

/** Password health, as internal/vault/health.go (shared cases: testdata/health.json). */
object PasswordHealth {
    const val WEAK_BITS = 50.0
    const val PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/"

    data class Report(val weak: List<String>, val reused: List<List<String>>)

    /** Too short or too guessable: under 8 characters, under 5 different ones, or under [WEAK_BITS] by
     *  length × log2(pool), where the pool counts 26 lowercase, 26 uppercase, 10 digits and 33 for anything else. */
    fun weak(pw: String): Boolean {
        val r = pw.codePoints().toArray()
        if (r.size < 8 || r.toSet().size < 5) return true
        var lower = false; var upper = false; var digit = false; var other = false
        for (c in r) when (c) {
            in 'a'.code..'z'.code -> lower = true
            in 'A'.code..'Z'.code -> upper = true
            in '0'.code..'9'.code -> digit = true
            else -> other = true
        }
        val pool = (if (lower) 26 else 0) + (if (upper) 26 else 0) + (if (digit) 10 else 0) + (if (other) 33 else 0)
        return r.size * (ln(pool.toDouble()) / ln(2.0)) < WEAK_BITS
    }

    /** Password items with a password, as id → password. */
    fun passwords(items: Map<String, Item>): Map<String, String> =
        items.filter { (_, it) -> it.isSecret && it.type == Item.PASSWORD && !it.fields["password"].isNullOrEmpty() }
            .mapValues { it.value.fields.getValue("password") }

    /** Weak ids, and groups of ids sharing a password (each sorted, groups by their first id). */
    fun check(items: Map<String, Item>): Report {
        val pws = passwords(items)
        return Report(
            weak = pws.filter { weak(it.value) }.keys.sorted(),
            reused = pws.entries.groupBy({ it.value }, { it.key }).values.filter { it.size > 1 }.map { it.sorted() }.sortedBy { it[0] },
        )
    }

    /** The uppercase SHA-1 split into the 5 characters sent to Have I Been Pwned and the rest. */
    fun pwnedHash(pw: String): Pair<String, String> {
        val h = MessageDigest.getInstance("SHA-1").digest(pw.toByteArray()).joinToString("") { "%02X".format(it) }
        return h.take(5) to h.drop(5)
    }

    /** How often [suffix] appears in a range answer ("SUFFIX:COUNT" lines; padding lines have count 0). */
    fun pwnedCount(body: String, suffix: String): Int {
        for (line in body.lineSequence()) {
            val parts = line.trim().split(':')
            if (parts.size == 2 && parts[0].equals(suffix, ignoreCase = true)) return parts[1].toIntOrNull() ?: 0
        }
        return 0
    }

    /** Asks Have I Been Pwned how often each password was seen in breaches; only the first 5 hex digits of each SHA-1
     *  leave the device, and answers are padded. Returns password → count for the ones that were seen. */
    suspend fun pwned(passwords: Collection<String>): Map<String, Int> {
        HttpClient(OkHttp) { install(HttpTimeout) { requestTimeoutMillis = 20_000 } }.use { http ->
            val found = mutableMapOf<String, Int>()
            for (pw in passwords.toSet()) {
                val (prefix, suffix) = pwnedHash(pw)
                val res = http.get(PWNED_RANGE_URL + prefix) { header("Add-Padding", "true") }
                if (!res.status.isSuccess()) throw ApiException(res.status.value, "Breach check failed (${res.status.value})")
                val n = pwnedCount(res.bodyAsText(), suffix)
                if (n > 0) found[pw] = n
            }
            return found
        }
    }
}
