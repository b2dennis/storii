package sh.base2.storii.core

/** URL matching, as internal/vault/match.go: the same host or a subdomain of the context's host. */
object Match {
    fun host(raw: String?): String {
        var s = raw?.trim().orEmpty()
        if (s.isEmpty()) return ""
        if (!s.contains("://")) s = "https://$s"
        var authority = s.substringAfter("://").takeWhile { it != '/' && it != '?' && it != '#' }
        authority = authority.substringAfterLast('@')
        var h = if (authority.startsWith("[")) {
            authority.substringAfter('[').substringBefore(']')
        } else {
            val colon = authority.lastIndexOf(':')
            if (colon >= 0 && authority.substring(colon + 1).all { it.isDigit() }) authority.substring(0, colon) else authority
        }
        h = h.lowercase().trimEnd('.')
        return h.removePrefix("www.")
    }

    fun matchesHost(contextUrl: String, pageHost: String): Boolean {
        val ch = host(contextUrl)
        val ph = host(pageHost)
        if (ch.isEmpty() || ph.isEmpty()) return false
        return ph == ch || ph.endsWith(".$ch")
    }
}
