package sh.base2.storii.core

import java.net.URLDecoder
import java.nio.ByteBuffer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** RFC 6238 codes and otpauth:// URIs, matching internal/vault/totp.go. */
data class Totp(
    val secret: ByteArray,
    val algorithm: String = "SHA1",
    val digits: Int = 6,
    val period: Int = 30,
    val issuer: String = "",
    val account: String = "",
) {
    fun code(nowMillis: Long = System.currentTimeMillis()): String {
        val counter = nowMillis / 1000 / period
        val mac = Mac.getInstance("Hmac$algorithm").apply { init(SecretKeySpec(secret, "Hmac$algorithm")) }
        val sum = mac.doFinal(ByteBuffer.allocate(8).putLong(counter).array())
        val off = sum.last().toInt() and 0x0f
        val v = (ByteBuffer.wrap(sum, off, 4).int and 0x7fffffff).toLong()
        var mod = 1L
        repeat(digits) { mod *= 10 }
        return (v % mod).toString().padStart(digits, '0')
    }

    fun remaining(nowMillis: Long = System.currentTimeMillis()) = period - ((nowMillis / 1000) % period).toInt()

    /** Inverse of [fromFields]; defaults are left out. */
    fun fields(): Map<String, String> = buildMap {
        put("secret", Base32.encode(secret))
        if (algorithm != "SHA1") put("algorithm", algorithm)
        if (digits != 6) put("digits", digits.toString())
        if (period != 30) put("period", period.toString())
        if (issuer.isNotEmpty()) put("issuer", issuer)
        if (account.isNotEmpty()) put("account", account)
    }

    override fun equals(other: Any?) = other is Totp && fields() == other.fields()
    override fun hashCode() = fields().hashCode()

    companion object {
        fun fromFields(f: Map<String, String>): Totp {
            val t = Totp(
                secret = Base32.decode(f["secret"].orEmpty()),
                algorithm = f["algorithm"]?.takeIf { it.isNotEmpty() }?.uppercase() ?: "SHA1",
                digits = f["digits"]?.takeIf { it.isNotEmpty() }?.let { it.toIntOrNull() ?: throw IllegalArgumentException("TOTP digits must be a number") } ?: 6,
                period = f["period"]?.takeIf { it.isNotEmpty() }?.let { it.toIntOrNull() ?: throw IllegalArgumentException("TOTP period must be a number") } ?: 30,
                issuer = f["issuer"].orEmpty(),
                account = f["account"].orEmpty(),
            )
            require(t.algorithm in setOf("SHA1", "SHA256", "SHA512")) { "unsupported TOTP algorithm ${t.algorithm}" }
            require(t.digits in 6..10) { "TOTP digits must be 6 to 10" }
            require(t.period in 1..300) { "TOTP period must be 1 to 300 seconds" }
            return t
        }

        /** Parses otpauth://totp/Issuer:account?secret=…, what 2FA QR codes contain. */
        fun parseUri(raw: String): Totp {
            val s = raw.trim()
            require(s.startsWith("otpauth://", ignoreCase = true)) { "not an otpauth:// URI" }
            val rest = s.substring("otpauth://".length)
            val slash = rest.indexOf('/')
            val host = if (slash < 0) rest.substringBefore('?') else rest.substring(0, slash)
            require(host.equals("totp", ignoreCase = true)) { "only TOTP (time-based) codes are supported" }
            val afterHost = if (slash < 0) "" else rest.substring(slash + 1)
            val label = percentDecode(afterHost.substringBefore('?'))
            val query = afterHost.substringAfter('?', "").split('&').filter { it.isNotEmpty() }.associate {
                val (k, v) = (it.split('=', limit = 2) + "").take(2)
                URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
            }
            val f = mutableMapOf(
                "secret" to query["secret"].orEmpty(), "algorithm" to query["algorithm"].orEmpty(),
                "digits" to query["digits"].orEmpty(), "period" to query["period"].orEmpty(), "issuer" to query["issuer"].orEmpty(),
            )
            val colon = label.indexOf(':')
            if (colon >= 0) {
                if (f["issuer"].isNullOrEmpty()) f["issuer"] = label.substring(0, colon).trim()
                f["account"] = label.substring(colon + 1).trim()
            } else {
                f["account"] = label
            }
            return fromFields(f)
        }

        /** Percent-decoding without turning '+' into a space (paths, unlike query strings, keep it). */
        private fun percentDecode(s: String): String {
            val out = java.io.ByteArrayOutputStream()
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '%' && i + 2 < s.length) {
                    val hex = s.substring(i + 1, i + 3).toIntOrNull(16)
                    if (hex != null) {
                        out.write(hex)
                        i += 3
                        continue
                    }
                }
                out.write(c.toString().toByteArray())
                i++
            }
            return out.toString("UTF-8")
        }
    }
}

object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    /** Lenient like Go's decoder: case, spaces, dashes and padding are ignored. */
    fun decode(input: String): ByteArray {
        val s = input.uppercase().filterNot { it == ' ' || it == '-' || it == '=' }
        require(s.isNotEmpty() && s.length % 8 !in setOf(1, 3, 6)) { "TOTP secret is not valid base32" }
        var bits = 0
        var value = 0
        val out = java.io.ByteArrayOutputStream()
        for (c in s) {
            val i = ALPHABET.indexOf(c)
            require(i >= 0) { "TOTP secret is not valid base32" }
            value = (value shl 5) or i
            bits += 5
            if (bits >= 8) {
                out.write((value ushr (bits - 8)) and 0xff)
                bits -= 8
            }
        }
        return out.toByteArray().also { require(it.isNotEmpty()) { "TOTP secret is not valid base32" } }
    }

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder()
        var bits = 0
        var value = 0
        for (b in bytes) {
            value = (value shl 8) or (b.toInt() and 0xff)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(value ushr (bits - 5)) and 31])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(ALPHABET[(value shl (5 - bits)) and 31])
        return sb.toString()
    }
}
