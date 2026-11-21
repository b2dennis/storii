package sh.base2.storii.data

import android.content.Context
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import sh.base2.storii.core.Backup
import sh.base2.storii.core.Api
import sh.base2.storii.core.ApiException
import sh.base2.storii.core.Crypto
import sh.base2.storii.core.Card
import sh.base2.storii.core.Entry
import sh.base2.storii.core.Item
import sh.base2.storii.core.PasswordHistory
import sh.base2.storii.core.Kdf
import sh.base2.storii.core.Match
import sh.base2.storii.core.RemoteItem
import sh.base2.storii.core.ShareCrypto
import sh.base2.storii.core.ShareMember
import sh.base2.storii.core.ShareMeta
import sh.base2.storii.core.StoriiJson
import sh.base2.storii.core.Write
import java.io.File
import java.util.UUID

/** What is kept on disk: the session token and the still-encrypted vault. Useless without the master password. */
@Serializable
data class VaultState(
    val server: String,
    val username: String,
    val token: String,
    val kdf: Kdf,
    @SerialName("wrapped_key") val wrappedKey: String,
    val revision: Long = 0,
    val items: Map<String, RemoteItem> = emptyMap(),
    val expired: Boolean = false,
    @SerialName("public_key") val publicKey: String = "",
    @SerialName("sealed_private_key") val sealedPrivateKey: String = "",
    val shares: Map<String, ShareState> = emptyMap(),
)

/** A share as kept on disk, still encrypted. */
@Serializable
data class ShareState(
    val owner: String,
    val meta: String,
    @SerialName("wrapped_key") val wrappedKey: String,
    val members: List<ShareMember> = emptyList(),
    val revision: Long = 0,
    val items: Map<String, RemoteItem> = emptyMap(),
)

/** A share this account can open. */
data class Share(val id: String, val name: String, val owner: String, val members: List<ShareMember>, val mine: Boolean)

sealed interface VaultStatus {
    data object NotSetUp : VaultStatus
    data class Locked(val username: String, val server: String, val expired: Boolean) : VaultStatus
    data class Unlocked(val username: String, val server: String, val items: Map<String, Item>) : VaultStatus
}

/** The app's single vault: the encrypted state on disk, and while unlocked the vault key and decrypted items in memory. */
class Vault(private val ctx: Context) {
    private val file = File(ctx.filesDir, "vault.json")
    private val mutex = Mutex()
    private var state: VaultState? = load()
    private var vaultKey: ByteArray? = null
    private var items: Map<String, Item> = emptyMap()
    /** Which share each shared item is in; personal items aren't listed. */
    private var itemShare: Map<String, String> = emptyMap()
    private var shareInfo: Map<String, Share> = emptyMap()
    private var shareKeys: Map<String, ByteArray> = emptyMap()
    private var sharePriv: ByteArray? = null

    private val _status = MutableStateFlow(computeStatus())
    val status: StateFlow<VaultStatus> = _status

    val isUnlocked get() = vaultKey != null
    val isSetUp get() = state != null

    private fun load(): VaultState? = runCatching { StoriiJson.decodeFromString(VaultState.serializer(), file.readText()) }.getOrNull()

    private fun save(s: VaultState) {
        val tmp = File(file.path + ".tmp")
        tmp.writeText(StoriiJson.encodeToString(VaultState.serializer(), s))
        tmp.renameTo(file)
        state = s
    }

    private fun computeStatus(): VaultStatus {
        val s = state ?: return VaultStatus.NotSetUp
        return if (vaultKey == null || s.expired) VaultStatus.Locked(s.username, s.server, s.expired)
        else VaultStatus.Unlocked(s.username, s.server, items)
    }

    private fun publish() {
        _status.value = computeStatus()
    }

    private fun decryptAll() {
        val key = vaultKey ?: return
        val s = state
        val all = s?.items.orEmpty().mapNotNull { (id, r) ->
            runCatching { id to Crypto.decryptItem(key, id, r.data!!) }.getOrNull()
        }.toMap().toMutableMap()
        val where = mutableMapOf<String, String>()
        val info = mutableMapOf<String, Share>()
        val keys = mutableMapOf<String, ByteArray>()
        sharePriv = s?.sealedPrivateKey?.takeIf { it.isNotEmpty() }?.let { runCatching { ShareCrypto.openPrivateKey(key, it) }.getOrNull() }
        val priv = sharePriv
        if (priv != null) for ((sid, sh) in s!!.shares) {
            val k = runCatching { ShareCrypto.unwrapShareKey(priv, sid, sh.wrappedKey) }.getOrNull() ?: continue
            keys[sid] = k
            val name = runCatching { ShareCrypto.openMeta(k, sid, sh.meta).name }.getOrDefault("")
            info[sid] = Share(sid, name, sh.owner, sh.members, sh.owner.equals(s.username, ignoreCase = true))
            for ((id, r) in sh.items) {
                if (id in all) continue // the same id in two places: the personal copy wins
                runCatching { ShareCrypto.decryptItem(k, sid, id, r.data!!) }.getOrNull()?.let { all[id] = it; where[id] = sid }
            }
        }
        items = all
        itemShare = where
        shareInfo = info
        shareKeys = keys
    }

    private fun deviceName() = "storii on ${Build.MANUFACTURER} ${Build.MODEL}".trim()

    suspend fun login(server: String, username: String, password: String, register: Boolean) = withContext(Dispatchers.IO) {
        var url = server.trim().trimEnd('/')
        if (!url.startsWith("http://") && !url.startsWith("https://")) url = "https://$url"
        val api = Api(url)
        api.ping()
        val key: ByteArray
        val resp = if (register) {
            val kdf = Crypto.newKdf()
            val keys = Crypto.deriveKeys(password, kdf)
            key = Crypto.randomBytes(32)
            api.register(username, kdf, keys.authKey, Crypto.wrapVaultKey(keys.wrap, key), deviceName())
        } else {
            val keys = Crypto.deriveKeys(password, api.prelogin(username))
            val r = api.login(username, keys.authKey, deviceName())
            key = Crypto.unwrapVaultKey(keys.wrap, r.account.wrappedKey)
            r
        }
        mutex.withLock {
            val s = VaultState(api.baseUrl, resp.account.username, resp.token, resp.account.kdf, resp.account.wrappedKey)
            save(pull(s))
            vaultKey = key
            decryptAll()
            runCatching { setupSharing() }
            Biometric.forget(ctx)
            publish()
        }
    }

    /** Unlocks with the master password. Works offline. Returns the vault key, for biometric enrolment. */
    suspend fun unlock(password: String): ByteArray = withContext(Dispatchers.Default) {
        val s = state ?: error("not set up")
        val keys = Crypto.deriveKeys(password, s.kdf)
        val key = try {
            Crypto.unwrapVaultKey(keys.wrap, s.wrappedKey)
        } catch (e: Exception) {
            throw IllegalArgumentException("Wrong master password")
        }
        unlockWithKey(key)
        key
    }

    fun unlockWithKey(key: ByteArray) {
        val s = state ?: error("not set up")
        // A key from biometrics must still open this account's vault.
        if (s.items.isNotEmpty()) {
            val (id, r) = s.items.entries.first()
            Crypto.decryptItem(key, id, r.data!!)
        }
        vaultKey = key
        decryptAll()
        publish()
    }

    fun lock() {
        vaultKey?.fill(0)
        vaultKey = null
        items = emptyMap()
        itemShare = emptyMap()
        shareInfo = emptyMap()
        shareKeys.values.forEach { it.fill(0) }
        shareKeys = emptyMap()
        sharePriv?.fill(0)
        sharePriv = null
        publish()
    }

    suspend fun logout() = withContext(Dispatchers.IO) {
        state?.let { s -> runCatching { Api(s.server, s.token).logout() } }
        lock()
        file.delete()
        state = null
        Biometric.forget(ctx)
        publish()
    }

    private suspend fun pull(s: VaultState): VaultState {
        val api = Api(s.server, s.token)
        val acct = api.account()
        val sync = api.sync(s.revision)
        // since=0 is a full snapshot without tombstones: replace, or deletions made elsewhere would never arrive.
        val map = if (s.revision == 0L) mutableMapOf() else s.items.toMutableMap()
        for (it in sync.items) if (it.deleted) map.remove(it.id) else map[it.id] = it
        return s.copy(kdf = acct.kdf, wrappedKey = acct.wrappedKey, revision = sync.revision, items = map,
            publicKey = acct.publicKey, sealedPrivateKey = acct.sealedPrivateKey, shares = pullShares(api, s.shares))
    }

    /** Follows the shares list: new shares are fetched whole, changed ones from their revision, gone ones dropped. */
    private suspend fun pullShares(api: Api, old: Map<String, ShareState>): Map<String, ShareState> {
        val list = try {
            api.shares()
        } catch (e: ApiException) {
            if (e.status == 404) return emptyMap() // a server from before sharing
            throw e
        }
        return list.associate { r ->
            var sh = old[r.id]?.takeIf { it.wrappedKey == r.wrappedKey } ?: ShareState(r.owner, r.meta, r.wrappedKey)
            sh = sh.copy(owner = r.owner, meta = r.meta, members = r.members)
            if (r.revision != sh.revision) {
                val sync = api.shareSync(r.id, sh.revision)
                val map = if (sh.revision == 0L) mutableMapOf() else sh.items.toMutableMap()
                for (it in sync.items) if (it.deleted) map.remove(it.id) else map[it.id] = it
                sh = sh.copy(revision = sync.revision, items = map)
            }
            r.id to sh
        }
    }

    /** Creates this account's sharing key pair if it has none yet, so others can add it to shares. */
    private suspend fun setupSharing() {
        val s = state ?: return
        val key = vaultKey ?: return
        if (s.publicKey.isNotEmpty()) return
        val (priv, pub) = ShareCrypto.newKeyPair()
        val api = Api(s.server, s.token)
        val acct = try {
            api.setShareKeys(Crypto.b64(pub), ShareCrypto.sealPrivateKey(key, priv))
        } catch (e: ApiException) {
            when (e.status) {
                404 -> return // a server from before sharing
                409 -> api.account() // another device got there first
                else -> throw e
            }
        }
        save(s.copy(publicKey = acct.publicKey, sealedPrivateKey = acct.sealedPrivateKey))
        decryptAll()
    }

    /** Fetches changes; marks the session expired when the server no longer accepts it. */
    suspend fun sync() = withContext(Dispatchers.IO) {
        mutex.withLock {
            val s = state ?: return@withLock
            try {
                save(pull(s))
            } catch (e: ApiException) {
                if (e.unauthorized) {
                    save(s.copy(expired = true))
                    lock()
                }
                throw e
            }
            decryptAll()
            runCatching { setupSharing() }
            publish()
        }
    }

    sealed interface Change {
        /** [share] places a new item in that share; existing items stay where they are. */
        data class Put(val id: String?, val item: Item, val share: String? = null) : Change
        data class Delete(val id: String) : Change
    }

    /** Uploads changes and applies them locally. Returns the ids, new ones included. */
    suspend fun write(changes: List<Change>): List<String> = withContext(Dispatchers.IO) {
        mutex.withLock {
            val s = state ?: error("not set up")
            val key = vaultKey ?: error("locked")
            val now = Item.now()
            val place = mutableMapOf<String, String>()
            val writes = changes.map { ch ->
                when (ch) {
                    is Change.Delete -> Write(ch.id, delete = true).also { place[ch.id] = itemShare[ch.id].orEmpty() }
                    is Change.Put -> {
                        val id = ch.id ?: UUID.randomUUID().toString()
                        val sid = if (id in items) itemShare[id].orEmpty() else ch.share.orEmpty()
                        place[id] = sid
                        var item = ch.item.copy(createdAt = ch.item.createdAt ?: now, updatedAt = now)
                        items[id]?.let { prev -> item = PasswordHistory.apply(prev, item, now) }
                        Write(id, encryptFor(key, sid, id, item))
                    }
                }
            }
            try {
                send(writes) { place[it].orEmpty() }
            } finally {
                decryptAll()
                publish()
            }
            writes.map { it.id }
        }
    }

    private fun encryptFor(vaultKey: ByteArray, shareId: String, id: String, item: Item): String =
        if (shareId.isEmpty()) Crypto.encryptItem(vaultKey, id, item)
        else ShareCrypto.encryptItem(shareKeys[shareId] ?: error("no such share"), shareId, id, item)

    /**
     * Uploads writes to the personal vault or the share [place] names, and keeps each chunk on disk once stored. The
     * server takes at most 2000 writes per request (a big import has more). Callers hold the mutex.
     */
    private suspend fun send(writes: List<Write>, place: (String) -> String) {
        for ((sid, ws) in writes.groupBy { place(it.id) }) for (chunk in ws.chunked(1000)) {
            val s = state ?: error("not set up")
            val api = Api(s.server, s.token)
            val rev = if (sid.isEmpty()) api.write(chunk) else api.shareWrite(sid, chunk)
            fun apply(m: Map<String, RemoteItem>) = m.toMutableMap().also { map ->
                for (w in chunk) if (w.delete) map.remove(w.id) else map[w.id] = RemoteItem(w.id, w.data, revision = rev)
            }
            save(if (sid.isEmpty()) s.copy(items = apply(s.items))
            else s.copy(shares = s.shares + (sid to s.shares.getValue(sid).let { it.copy(items = apply(it.items)) })))
        }
    }

    suspend fun put(id: String?, item: Item) = write(listOf(Change.Put(id, item))).first()

    /** Deletes items; deleting a context also unlinks it from its secrets. */
    suspend fun delete(ids: List<String>) {
        val changes = items.filter { (sid, s) -> sid !in ids && s.contexts.any { it in ids } }
            .map { (sid, s) -> Change.Put(sid, s.copy(contexts = s.contexts - ids.toSet())) } + ids.map { Change.Delete(it) }
        write(changes)
    }

    /** A deleted item from the server's trash, with its ciphertext so a restore puts back exactly what was there. */
    data class Deleted(val id: String, val item: Item, val deletedAt: String, internal val data: String)

    /** The trash, decrypted (entries this vault key can't read are left out), and how many days it keeps items. */
    suspend fun trash(): Pair<List<Deleted>, Int> = withContext(Dispatchers.IO) {
        val s = state ?: error("not set up")
        val key = vaultKey ?: error("locked")
        val t = Api(s.server, s.token).trash()
        t.items.mapNotNull { d -> runCatching { Deleted(d.id, Crypto.decryptItem(key, d.id, d.data), d.deletedAt, d.data) }.getOrNull() } to t.days
    }

    /** Puts deleted items back under their ids, as they were. */
    suspend fun restore(deleted: List<Deleted>) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val s = state ?: error("not set up")
            vaultKey ?: error("locked")
            val map = s.items.toMutableMap()
            try {
                for (chunk in deleted.map { Write(it.id, it.data) }.chunked(1000)) {
                    val rev = Api(s.server, s.token).write(chunk)
                    for (w in chunk) map[w.id] = RemoteItem(w.id, w.data, revision = rev)
                    save(s.copy(items = map.toMap()))
                }
            } finally {
                decryptAll()
                publish()
            }
        }
    }

    suspend fun emptyTrash(ids: List<String>) = withContext(Dispatchers.IO) {
        val s = state ?: error("not set up")
        Api(s.server, s.token).emptyTrash(ids)
    }

    /** An encrypted backup of every item (the file's text), sealed with [password]. */
    suspend fun backup(password: String): String = withContext(Dispatchers.Default) {
        val s = state ?: error("not set up")
        val key = vaultKey ?: error("locked")
        val plain = s.items.mapNotNull { (id, r) ->
            runCatching { id to StoriiJson.parseToJsonElement(String(Crypto.open(key, r.data!!, "storii:item:$id"))) }.getOrNull()
        }.toMap().toMutableMap()
        // Shared items too: a backup holds everything this vault shows.
        for ((id, sid) in itemShare) {
            val r = s.shares[sid]?.items?.get(id) ?: continue
            runCatching { plain[id] = StoriiJson.parseToJsonElement(String(ShareCrypto.openItem(shareKeys.getValue(sid), sid, id, r.data!!))) }
        }
        Backup.seal(password, plain)
    }

    /** Opens a backup and says what restoring it would add (items this vault doesn't have) and skip. */
    suspend fun planRestore(password: String, text: String): Backup.Plan = withContext(Dispatchers.Default) {
        val s = state ?: error("not set up")
        Backup.plan(Backup.open(password, text), items.keys)
    }

    /** Adds [plan]'s items exactly as they were backed up, under their ids. */
    suspend fun restoreBackup(plan: Backup.Plan) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val s = state ?: error("not set up")
            val key = vaultKey ?: error("locked")
            val writes = plan.add.filter { it.first !in items }.map { (id, _, raw) -> Write(id, Crypto.encryptRaw(key, id, raw, Crypto.randomBytes(12))) }
            val map = s.items.toMutableMap()
            try {
                for (chunk in writes.chunked(1000)) {
                    val rev = Api(s.server, s.token).write(chunk)
                    for (w in chunk) map[w.id] = RemoteItem(w.id, w.data, revision = rev)
                    save(s.copy(items = map.toMap()))
                }
            } finally {
                decryptAll()
                publish()
            }
            writes.size
        }
    }

    // Sharing.

    /** This account's key fingerprint, for others to compare when they add it; empty before sharing is set up. */
    fun fingerprint(): String = state?.publicKey?.takeIf { it.isNotEmpty() }?.let { ShareCrypto.fingerprint(Crypto.unb64(it)) }.orEmpty()
    fun shares(): List<Share> = shareInfo.values.sortedWith(compareBy({ it.name.lowercase() }, { it.id }))
    /** The share an item is in, or null for the personal vault. */
    fun shareOf(id: String): Share? = itemShare[id]?.let { shareInfo[it] }
    val username get() = state?.username.orEmpty()

    private suspend fun needSharing(): ByteArray {
        if (sharePriv == null) setupSharing()
        return sharePriv ?: error("Sharing isn't set up: the server may be too old.")
    }

    private fun api(): Api = state!!.let { Api(it.server, it.token) }

    suspend fun createShare(name: String): Share = withContext(Dispatchers.IO) {
        mutex.withLock {
            val priv = needSharing()
            val n = name.trim().ifEmpty { error("A share needs a name.") }
            val id = UUID.randomUUID().toString()
            val key = Crypto.randomBytes(32)
            val wrapped = ShareCrypto.wrapShareKey(ShareCrypto.publicKeyOf(priv), id, key)
            val meta = ShareCrypto.sealMeta(key, id, ShareMeta(n))
            api().createShare(id, meta, wrapped)
            val s = state!!
            save(s.copy(shares = s.shares + (id to ShareState(s.username, meta, wrapped, listOf(ShareMember(s.username, s.publicKey, owner = true))))))
            decryptAll()
            publish()
            shareInfo.getValue(id)
        }
    }

    suspend fun renameShare(id: String, name: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = shareKeys[id] ?: error("no such share")
            val meta = ShareCrypto.sealMeta(key, id, ShareMeta(name.trim()))
            api().renameShare(id, meta)
            val s = state!!
            save(s.copy(shares = s.shares + (id to s.shares.getValue(id).copy(meta = meta))))
            decryptAll()
            publish()
        }
    }

    /** Someone's public key and its fingerprint, to compare with them before adding them: (username, key, fingerprint). */
    suspend fun memberKey(username: String): Triple<String, String, String> = withContext(Dispatchers.IO) {
        val k = api().userKey(username.trim())
        val pub = runCatching { Crypto.unb64(k.publicKey) }.getOrNull()?.takeIf { it.size == 32 } ?: error("The server sent a malformed key.")
        Triple(k.username, k.publicKey, ShareCrypto.fingerprint(pub))
    }

    suspend fun addMember(id: String, username: String, publicKey: String) {
        withContext(Dispatchers.IO) {
            val key = shareKeys[id] ?: error("no such share")
            api().addShareMember(id, username, ShareCrypto.wrapShareKey(Crypto.unb64(publicKey), id, key))
        }
        sync()
    }

    /** Takes someone out of a share. They keep whatever they copied before. */
    suspend fun removeMember(id: String, username: String) {
        withContext(Dispatchers.IO) { api().removeShareMember(id, username) }
        sync()
    }

    /** Deletes a share with its items (owner) or leaves it (members). */
    suspend fun deleteShare(id: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            api().deleteShare(id)
            val s = state!!
            save(s.copy(shares = s.shares - id))
            decryptAll()
            publish()
        }
    }

    /**
     * Puts items into a share ([shareId] "" = the personal vault) under the same ids. Contexts a moved secret links go
     * along when nothing staying behind uses them; otherwise the secret gets a copy. Writes the new place first, so a
     * failure halfway leaves a copy rather than nothing.
     */
    suspend fun move(ids: List<String>, shareId: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            val key = vaultKey ?: error("locked")
            if (shareId.isNotEmpty() && shareId !in shareKeys) error("no such share")
            val moving = ids.filter { itemShare[it].orEmpty() != shareId }.onEach { require(it in items) { "no such item $it" } }.toMutableSet()
            val out = moving.associateWith { items.getValue(it) }.toMutableMap()
            val copies = mutableSetOf<String>()
            for (id in moving.toList()) {
                val it = out.getValue(id)
                if (!it.isSecret) continue
                val ctxs = it.contexts.toMutableList()
                for ((i, c) in it.contexts.withIndex()) {
                    if (c in moving || itemShare[c].orEmpty() == shareId) continue
                    val ctxItem = items[c] ?: continue
                    val usedElsewhere = items.any { (sid, s) -> sid !in moving && c in s.contexts }
                    if (!usedElsewhere) {
                        moving += c
                        out[c] = ctxItem
                    } else {
                        val copy = UUID.randomUUID().toString()
                        out[copy] = ctxItem.copy(createdAt = null)
                        copies += copy
                        ctxs[i] = copy
                    }
                }
                out[id] = it.copy(contexts = ctxs)
            }
            if (out.isEmpty()) return@withLock
            val now = Item.now()
            val from = moving.associateWith { itemShare[it].orEmpty() }
            val puts = out.map { (id, it) -> Write(id, encryptFor(key, shareId, id, it.copy(createdAt = it.createdAt ?: now))) }
            try {
                send(puts) { shareId }
                send(from.keys.map { Write(it, delete = true) }) { from[it].orEmpty() }
                // A moved item isn't deleted: keep it out of the personal trash, where restoring it would duplicate it.
                val personalGone = from.filterValues { it.isEmpty() }.keys.toList()
                if (personalGone.isNotEmpty()) runCatching { api().emptyTrash(personalGone) }
            } finally {
                decryptAll()
                publish()
            }
        }
    }

    fun secrets(): List<Entry> = items.filter { it.value.isSecret }.map { Entry(it.key, it.value) }.sortedBy { it.item.name.lowercase() }
    fun contexts(): List<Entry> = items.filter { it.value.isContext }.map { Entry(it.key, it.value) }.sortedBy { it.item.name.lowercase() }
    fun get(id: String) = items[id]

    /** Secrets in contexts matching a web host (preferred when known) or an Android app. */
    fun forTarget(webHost: String?, androidPackage: String?): List<Entry> {
        val ctxIds = items.filter { (_, it) -> if (!webHost.isNullOrBlank()) it.matches(webHost, null) else it.matches(null, androidPackage) }.keys
        return secrets().filter { e -> e.item.contexts.any { it in ctxIds } }
    }

    /**
     * Links a secret to the app or site it was just used for, creating a context if needed. Used after picking a secret
     * manually in autofill, so it is offered directly next time.
     */
    suspend fun remember(secretId: String, webHost: String?, androidPackage: String?, appLabel: String?) {
        val secret = items[secretId] ?: return
        val existing = contexts().firstOrNull { (_, c) ->
            if (!webHost.isNullOrBlank()) c.urls.any { Match.matchesHost(it, webHost) } else androidPackage in c.androidPackages
        }
        val changes = mutableListOf<Change>()
        val ctxId = existing?.id ?: UUID.randomUUID().toString().also { id ->
            changes += Change.Put(id, if (!webHost.isNullOrBlank())
                Item(kind = Item.KIND_CONTEXT, name = Match.host(webHost), contextType = "website", urls = listOf("https://${Match.host(webHost)}"))
            else Item(kind = Item.KIND_CONTEXT, name = appLabel ?: androidPackage!!, contextType = "app", androidPackages = listOf(androidPackage!!)))
        }
        if (ctxId !in secret.contexts) changes += Change.Put(secretId, secret.copy(contexts = secret.contexts + ctxId))
        if (changes.isNotEmpty()) write(changes)
    }

    /** Saves a login captured by autofill: updates the password of a known username, or adds a new secret. */
    /**
     * Saves a submitted login. [changed] means it came from a new-password field (signup, reset, change password): with
     * no username, it updates the login whose password was [current], or the site's only login.
     */
    suspend fun saveLogin(webHost: String?, androidPackage: String?, appLabel: String?, username: String, password: String,
                          changed: Boolean = false, current: String = "") {
        val known = forTarget(webHost, androidPackage).filter { it.item.type == Item.PASSWORD }
        if (known.any { it.item.field("password") == password && (username.isEmpty() || it.item.field("username") == username) }) return
        val same = loginToUpdate(known, username, password, changed, current)
        if (same != null) {
            val fields = same.item.fields + ("password" to password) + (if (username.isNotEmpty()) mapOf("username" to username) else emptyMap())
            put(same.id, same.item.copy(fields = fields))
            return
        }
        val name = if (!webHost.isNullOrBlank()) Match.host(webHost) else appLabel ?: androidPackage ?: "Login"
        val id = put(null, Item(kind = Item.KIND_SECRET, type = Item.PASSWORD, name = name,
            fields = buildMap { if (username.isNotEmpty()) put("username", username); put("password", password) }))
        remember(id, webHost, androidPackage, appLabel)
    }

    /** A card typed into a form (fields from Card.fromForm), unless storii has that number already. */
    suspend fun saveCard(fields: Map<String, String>) {
        val number = fields["number"] ?: return
        if (secrets().any { it.item.type == Item.CARD && Card.digits(it.item.field("number")) == number }) return
        put(null, Item(kind = Item.KIND_SECRET, type = Item.CARD, name = Card.defaultName(number), fields = fields))
    }

    companion object {
        fun loginToUpdate(known: List<Entry>, username: String, password: String, changed: Boolean, current: String): Entry? =
            known.firstOrNull { username.isNotEmpty() && it.item.field("username") == username }
                // A login without a username (e.g. migrated from v1) used with this password: add the username to it.
                ?: known.firstOrNull { username.isNotEmpty() && it.item.field("username").isEmpty() && it.item.field("password") == password }
                ?: if (changed && username.isEmpty()) {
                    known.firstOrNull { current.isNotEmpty() && it.item.field("password") == current } ?: known.singleOrNull()
                } else null
    }
}
