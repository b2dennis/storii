package sh.base2.storii.core

/**
 * Brings logins over from other password managers' CSV exports: Google Password Manager (this phone's, Chrome's or
 * passwords.google.com), Firefox, Bitwarden and 1Password. The same rules as the CLI's `storii import`
 * (internal/importer), checked against the shared cases in testdata/import:
 *
 * - each row becomes a password secret with a website or Android app context (an existing one is reused);
 * - a row already in the vault (same site, username and password) is skipped, so importing twice is safe;
 * - a row matching a login without a username (as storii v1 migrated them) fills that username in.
 */
object Import {
    data class Row(val name: String, val url: String, val username: String, val password: String, val note: String)

    enum class Action { ADD, USERNAME, SKIP, INVALID }

    /** What happens to one row. [id] is the secret written. */
    data class Line(val action: Action, val id: String? = null, val name: String, val site: String = "", val differs: Boolean = false)

    data class Plan(val writes: Map<String, Item>, val lines: List<Line>) {
        fun count(a: Action) = lines.count { it.action == a }
    }

    class NotAnExport(message: String) : Exception(message)

    private val columns = mapOf(
        "name" to listOf("name", "title"),
        "url" to listOf("url", "login_uri", "website", "web site"),
        "username" to listOf("username", "login_username", "login"),
        "password" to listOf("password", "login_password"),
        "note" to listOf("note", "notes", "extra"),
    )

    fun parse(text: String): List<Row> {
        val records = csv(text.removePrefix("\uFEFF"))
        val header = records.firstOrNull() ?: throw NotAnExport("The file is empty.")
        val idx = mutableMapOf<String, Int>()
        header.forEachIndexed { i, h ->
            val name = h.trim().lowercase()
            for ((field, names) in columns) if (field !in idx && name in names) idx[field] = i
        }
        if ("password" !in idx) throw NotAnExport("This doesn't look like a password export: it has no password column.")
        return records.drop(1).filter { r -> r.any { it.isNotEmpty() } }.map { r ->
            fun get(f: String) = idx[f]?.let { r.getOrNull(it) }.orEmpty()
            Row(get("name").trim(), get("url").trim(), get("username").trim(), get("password"), get("note").trim())
        }
    }

    /** RFC 4180, as Go's encoding/csv reads it: quoted fields may hold commas, quotes ("") and line breaks (\r\n → \n). */
    internal fun csv(text: String): List<List<String>> {
        val records = mutableListOf<List<String>>()
        var record = mutableListOf<String>()
        val field = StringBuilder()
        var quoted = false
        var i = 0
        fun endField() { record.add(field.toString()); field.clear() }
        fun endRecord() { endField(); records.add(record); record = mutableListOf() }
        while (i < text.length) {
            val c = text[i]
            if (quoted) {
                when {
                    c == '"' && text.getOrNull(i + 1) == '"' -> { field.append('"'); i++ }
                    c == '"' -> quoted = false
                    c == '\r' && text.getOrNull(i + 1) == '\n' -> { field.append('\n'); i++ }
                    else -> field.append(c)
                }
            } else when (c) {
                '"' -> if (field.isEmpty()) quoted = true else field.append(c)
                ',' -> endField()
                '\r' -> { if (text.getOrNull(i + 1) == '\n') i++; endRecord() }
                '\n' -> endRecord()
                else -> field.append(c)
            }
            i++
        }
        if (field.isNotEmpty() || record.isNotEmpty()) endRecord()
        return records
    }

    /** Where a login is used: a web host or an Android package. */
    private data class Site(val host: String = "", val pkg: String = "") {
        val empty get() = host.isEmpty() && pkg.isEmpty()
        override fun toString() = pkg.ifEmpty { host }
    }

    private fun siteOf(r: Row): Site {
        if (r.url.startsWith("android://", ignoreCase = true)) {
            return Site(pkg = r.url.substring("android://".length).substringAfterLast('@').substringBefore('/'))
        }
        Match.host(r.url).takeIf { it.isNotEmpty() }?.let { return Site(host = it) }
        if (looksLikeDomain(r.name)) return Site(host = Match.host(r.name))
        return Site()
    }

    /** Matches rows against the vault (id -> item). [newId] makes ids for new items. */
    fun build(existing: Map<String, Item>, rows: List<Row>, newId: () -> String, now: String = Item.now()): Plan {
        val items = existing.toMutableMap()
        val writes = linkedMapOf<String, Item>()
        fun put(id: String, it: Item) { items[id] = it; writes[id] = it }
        val lines = rows.map { r ->
            if (r.password.isEmpty()) return@map Line(Action.INVALID, name = r.name)
            val s = siteOf(r)
            val name = r.name.ifEmpty { s.toString() }
            var same: String? = null
            var noUser: String? = null
            var sameUser: String? = null
            for (id in items.keys.sorted()) {
                val it = items.getValue(id)
                if (!it.isSecret || it.type != Item.PASSWORD) continue
                if (s.empty) {
                    if (!it.name.equals(name, ignoreCase = true) || it.contexts.isNotEmpty()) continue
                } else if (it.contexts.none { c -> items[c]?.let { ctx -> contextFor(ctx, s) } == true }) continue
                val u = it.field("username")
                val pw = it.field("password")
                when {
                    u == r.username && pw == r.password -> same = id
                    u.isEmpty() && pw == r.password && r.username.isNotEmpty() && noUser == null -> noUser = id
                    u == r.username && sameUser == null -> sameUser = id
                }
            }
            when {
                same != null -> Line(Action.SKIP, same, name, s.toString())
                noUser != null -> {
                    val it = items.getValue(noUser!!)
                    put(noUser!!, it.copy(fields = it.fields + ("username" to r.username), updatedAt = now))
                    Line(Action.USERNAME, noUser, name, s.toString())
                }
                else -> {
                    var contexts = emptyList<String>()
                    if (!s.empty) {
                        val ctxId = items.keys.sorted().firstOrNull { contextFor(items.getValue(it), s) } ?: newId().also { id ->
                            put(id, if (s.pkg.isNotEmpty()) {
                                Item(kind = Item.KIND_CONTEXT, name = name, contextType = "app", androidPackages = listOf(s.pkg), createdAt = now, updatedAt = now)
                            } else {
                                val scheme = if (r.url.startsWith("http://", ignoreCase = true)) "http" else "https"
                                Item(kind = Item.KIND_CONTEXT, name = s.host, contextType = "website", urls = listOf("$scheme://${s.host}"), createdAt = now, updatedAt = now)
                            })
                        }
                        contexts = listOf(ctxId)
                    }
                    val fields = buildMap {
                        if (r.username.isNotEmpty()) put("username", r.username)
                        put("password", r.password)
                    }
                    val id = newId()
                    put(id, Item(kind = Item.KIND_SECRET, type = Item.PASSWORD, name = name, contexts = contexts, fields = fields,
                        notes = r.note.ifEmpty { null }, createdAt = now, updatedAt = now))
                    Line(Action.ADD, id, name, s.toString(), differs = sameUser != null)
                }
            }
        }
        return Plan(writes, lines)
    }

    private fun contextFor(ctx: Item, s: Site): Boolean {
        if (!ctx.isContext) return false
        if (s.pkg.isNotEmpty()) return s.pkg in ctx.androidPackages
        return ctx.urls.any { Match.host(it) == s.host }
    }

    private fun looksLikeDomain(s: String): Boolean {
        if (s.any { it in " /@" } || '.' !in s) return false
        val tld = s.substringAfterLast('.')
        return tld.length >= 2 && tld.all { it in 'a'..'z' }
    }
}
