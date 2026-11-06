package sh.base2.storii.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.time.Instant
import java.time.temporal.ChronoUnit

val StoriiJson = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = false
}

@Serializable
data class Kdf(
    val alg: String = "argon2id",
    val salt: String,
    val iterations: Int = 3,
    @SerialName("memory_kib") val memoryKib: Int = 65536,
    val parallelism: Int = 2,
)

@Serializable
data class CustomField(val name: String, val value: String, val hidden: Boolean = false)

/** The decrypted JSON of one item: a secret or a context. */
@Serializable
data class Item(
    val kind: String,
    val name: String,
    val type: String? = null,
    val contexts: List<String> = emptyList(),
    val fields: Map<String, String> = emptyMap(),
    val custom: List<CustomField> = emptyList(),
    @SerialName("context_type") val contextType: String? = null,
    val urls: List<String> = emptyList(),
    @SerialName("android_packages") val androidPackages: List<String> = emptyList(),
    val notes: String? = null,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("updated_at") val updatedAt: String? = null,
) {
    val isSecret get() = kind == KIND_SECRET
    val isContext get() = kind == KIND_CONTEXT
    fun field(name: String) = fields[name].orEmpty()

    /** Does this context apply to a web host or an Android app? */
    fun matches(host: String?, androidPackage: String?): Boolean {
        if (!isContext) return false
        if (!host.isNullOrBlank() && urls.any { Match.matchesHost(it, host) }) return true
        return !androidPackage.isNullOrBlank() && androidPackage in androidPackages
    }

    companion object {
        const val KIND_SECRET = "secret"
        const val KIND_CONTEXT = "context"
        const val PASSWORD = "password"
        const val TOTP = "totp"
        const val API_KEY = "api_key"
        const val NOTE = "note"
        val TYPES = listOf(PASSWORD, TOTP, API_KEY, NOTE)

        fun now(): String = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString()
    }
}

/** An item with its id. */
data class Entry(val id: String, val item: Item)

fun typeLabel(type: String?) = when (type) {
    Item.PASSWORD -> "Password"
    Item.TOTP -> "2FA code"
    Item.API_KEY -> "API key"
    Item.NOTE -> "Note"
    else -> type ?: "?"
}
