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
import sh.base2.storii.core.Api
import sh.base2.storii.core.ApiException
import sh.base2.storii.core.Crypto
import sh.base2.storii.core.Entry
import sh.base2.storii.core.Item
import sh.base2.storii.core.Kdf
import sh.base2.storii.core.Match
import sh.base2.storii.core.RemoteItem
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
)

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
        items = state?.items.orEmpty().mapNotNull { (id, r) ->
            runCatching { id to Crypto.decryptItem(key, id, r.data!!) }.getOrNull()
        }.toMap()
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
        return s.copy(kdf = acct.kdf, wrappedKey = acct.wrappedKey, revision = sync.revision, items = map)
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
            publish()
        }
    }

    sealed interface Change {
        data class Put(val id: String?, val item: Item) : Change
        data class Delete(val id: String) : Change
    }

    /** Uploads changes and applies them locally. Returns the ids, new ones included. */
    suspend fun write(changes: List<Change>): List<String> = withContext(Dispatchers.IO) {
        mutex.withLock {
            val s = state ?: error("not set up")
            val key = vaultKey ?: error("locked")
            val now = Item.now()
            val writes = changes.map { ch ->
                when (ch) {
                    is Change.Delete -> Write(ch.id, delete = true)
                    is Change.Put -> {
                        val id = ch.id ?: UUID.randomUUID().toString()
                        val item = ch.item.copy(createdAt = ch.item.createdAt ?: now, updatedAt = now)
                        Write(id, Crypto.encryptItem(key, id, item))
                    }
                }
            }
            val rev = Api(s.server, s.token).write(writes)
            val map = s.items.toMutableMap()
            for (w in writes) if (w.delete) map.remove(w.id) else map[w.id] = RemoteItem(w.id, w.data, revision = rev)
            save(s.copy(items = map))
            decryptAll()
            publish()
            writes.map { it.id }
        }
    }

    suspend fun put(id: String?, item: Item) = write(listOf(Change.Put(id, item))).first()

    /** Deletes items; deleting a context also unlinks it from its secrets. */
    suspend fun delete(ids: List<String>) {
        val changes = items.filter { (sid, s) -> sid !in ids && s.contexts.any { it in ids } }
            .map { (sid, s) -> Change.Put(sid, s.copy(contexts = s.contexts - ids.toSet())) } + ids.map { Change.Delete(it) }
        write(changes)
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
