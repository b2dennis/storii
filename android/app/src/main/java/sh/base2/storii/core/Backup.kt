package sh.base2.storii.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.time.temporal.ChronoUnit

/**
 * Encrypted storii backups (internal/vault/backup.go has the format): every item's plaintext keyed by id, sealed with a
 * key derived from a backup password like the login keys (Argon2id + HKDF "storii wrap"), with AAD "storii:backup".
 */
object Backup {
    const val VERSION = 1
    private const val AAD = "storii:backup"
    private val uuid = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
    // The file spells out every KDF parameter (StoriiJson leaves defaults out).
    private val fileJson = Json { ignoreUnknownKeys = true; encodeDefaults = true; prettyPrint = true }

    class WrongPassword : Exception("Wrong backup password, or the file is damaged.")
    class NotABackup(msg: String = "That isn't a storii backup.") : Exception(msg)

    @Serializable
    private data class File(
        @SerialName("storii_backup") val version: Int,
        @SerialName("exported_at") val exportedAt: String,
        val kdf: Kdf,
        val data: String,
    )

    @Serializable
    private data class Contents(val items: Map<String, JsonElement>)

    fun isBackup(text: String): Boolean = runCatching {
        ((StoriiJson.parseToJsonElement(text) as JsonObject)["storii_backup"]?.jsonPrimitive?.intOrNull ?: 0) > 0
    }.getOrDefault(false)

    /** [items]: id → item JSON. Returns the file's text. */
    fun seal(password: String, items: Map<String, JsonElement>, kdf: Kdf = Crypto.newKdf(), now: Instant = Instant.now(),
             nonce: ByteArray = Crypto.randomBytes(12)): String {
        val keys = Crypto.deriveKeys(password, kdf)
        val plain = StoriiJson.encodeToString(Contents.serializer(), Contents(items)).toByteArray()
        val data = Crypto.seal(keys.wrap, plain, AAD, nonce)
        return fileJson.encodeToString(File.serializer(), File(VERSION, now.truncatedTo(ChronoUnit.SECONDS).toString(), kdf, data))
    }

    /** Returns id → item JSON. */
    fun open(password: String, text: String): Map<String, JsonElement> {
        if (!isBackup(text)) throw NotABackup()
        val f = runCatching { fileJson.decodeFromString(File.serializer(), text) }.getOrElse { throw NotABackup("That backup is damaged.") }
        if (f.version != VERSION) throw NotABackup("This backup (version ${f.version}) needs a newer storii.")
        val keys = Crypto.deriveKeys(password, f.kdf)
        val plain = try {
            Crypto.open(keys.wrap, f.data, AAD)
        } catch (e: DecryptionException) {
            throw WrongPassword()
        }
        return StoriiJson.decodeFromString(Contents.serializer(), String(plain)).items
    }

    /** What restoring adds: the backup's valid items the vault doesn't have ([have]), sorted by name, as (id, item, raw JSON). */
    data class Plan(val add: List<Triple<String, Item, String>>, val skipped: Int)

    fun plan(items: Map<String, JsonElement>, have: Set<String>): Plan {
        var skipped = 0
        val add = items.mapNotNull { (id, el) ->
            val item = runCatching { StoriiJson.decodeFromJsonElement(Item.serializer(), el) }.getOrNull()
            if (!uuid.matches(id) || id in have || item == null || item.name.isBlank() || !(item.isSecret || item.isContext)) {
                skipped++
                null
            } else Triple(id, item, el.toString())
        }.sortedBy { it.second.name.lowercase() }
        return Plan(add, skipped)
    }
}
