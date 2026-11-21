package sh.base2.storii.core

import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.HttpTimeout
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.header
import io.ktor.client.request.request
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

class ApiException(val status: Int, message: String) : Exception(message) {
    val unauthorized get() = status == 401
}

@Serializable
data class Account(
    val username: String,
    val kdf: Kdf,
    @SerialName("wrapped_key") val wrappedKey: String,
    val revision: Long = 0,
    @SerialName("public_key") val publicKey: String = "",
    @SerialName("sealed_private_key") val sealedPrivateKey: String = "",
)

@Serializable
data class ShareMember(val username: String, @SerialName("public_key") val publicKey: String = "", val owner: Boolean = false)

/** A share as the server lists it; meta and the wrapped key are encrypted. */
@Serializable
data class RemoteShare(
    val id: String,
    val owner: String,
    val meta: String,
    @SerialName("wrapped_key") val wrappedKey: String,
    val members: List<ShareMember> = emptyList(),
    val revision: Long = 0,
)

@Serializable
private data class SharesResp(val shares: List<RemoteShare> = emptyList())

@Serializable
private data class ShareKeys(@SerialName("public_key") val publicKey: String, @SerialName("sealed_private_key") val sealedPrivateKey: String)

@Serializable
data class UserKey(val username: String, @SerialName("public_key") val publicKey: String)

@Serializable
private data class NewShare(val id: String, val meta: String, @SerialName("wrapped_key") val wrappedKey: String)

@Serializable
private data class ShareMetaReq(val meta: String)

@Serializable
private data class WrappedKeyReq(@SerialName("wrapped_key") val wrappedKey: String)

@Serializable
data class SessionResp(val token: String, val account: Account)

@Serializable
data class RemoteItem(val id: String, val data: String? = null, val deleted: Boolean = false, val revision: Long = 0)

@Serializable
data class SyncResp(val revision: Long, val items: List<RemoteItem>)

@Serializable
data class Write(val id: String, val data: String? = null, val delete: Boolean = false)

@Serializable
data class TrashItem(val id: String, val data: String, @SerialName("deleted_at") val deletedAt: String)

@Serializable
data class TrashResp(val items: List<TrashItem>, val days: Int)

@Serializable
private data class TrashIds(val ids: List<String>)

@Serializable
private data class Writes(val writes: List<Write>)

@Serializable
private data class RevisionResp(val revision: Long)

@Serializable
private data class Prelogin(val kdf: Kdf)

@Serializable
private data class Ping(val api: String = "")

/** The storii v2 HTTP API. */
class Api(baseUrl: String, var token: String = "") {
    val baseUrl = baseUrl.trim().trimEnd('/')

    private suspend fun <T> call(method: HttpMethod, path: String, body: Any?, ser: KSerializer<T>?): T? {
        val res = client.request(baseUrl + path) {
            this.method = method
            if (token.isNotEmpty()) header("Authorization", "Bearer $token")
            if (body != null) {
                contentType(ContentType.Application.Json)
                setBody(body)
            }
        }
        val text = res.bodyAsText()
        if (res.status.value >= 300) {
            val msg = runCatching { StoriiJson.parseToJsonElement(text) as JsonObject }.getOrNull()
                ?.get("error")?.jsonPrimitive?.content ?: "server answered ${res.status.value}"
            throw ApiException(res.status.value, msg)
        }
        return if (ser == null || text.isEmpty()) null else StoriiJson.decodeFromString(ser, text)
    }

    suspend fun ping() {
        val p = call(HttpMethod.Get, "/api/v2/ping", null, Ping.serializer())
        if (p?.api != "v2") throw ApiException(0, "that is not a storii v2 server")
    }

    suspend fun prelogin(username: String) = call(HttpMethod.Post, "/api/v2/prelogin", mapOf("username" to username), Prelogin.serializer())!!.kdf

    suspend fun login(username: String, authKey: String, device: String) = call(HttpMethod.Post, "/api/v2/login",
        mapOf("username" to username, "auth_key" to authKey, "device_name" to device), SessionResp.serializer())!!

    suspend fun register(username: String, kdf: Kdf, authKey: String, wrappedKey: String, device: String) =
        call(HttpMethod.Post, "/api/v2/register", RegisterReq(username, kdf, authKey, wrappedKey, device), SessionResp.serializer())!!

    suspend fun logout() = call(HttpMethod.Post, "/api/v2/logout", null, Unit.serializer())
    suspend fun account() = call(HttpMethod.Get, "/api/v2/account", null, Account.serializer())!!
    suspend fun sync(since: Long) = call(HttpMethod.Get, "/api/v2/sync?since=$since", null, SyncResp.serializer())!!
    /** Deleted items the server still keeps, newest first. */
    suspend fun trash() = call(HttpMethod.Get, "/api/v2/trash", null, TrashResp.serializer())!!
    /** Forgets deleted items for good: [ids], or all of them when it's empty. */
    suspend fun emptyTrash(ids: List<String>) { call(HttpMethod.Delete, "/api/v2/trash", TrashIds(ids), Unit.serializer()) }
    suspend fun write(writes: List<Write>) = call(HttpMethod.Post, "/api/v2/items", Writes(writes), RevisionResp.serializer())!!.revision

    suspend fun shares() = call(HttpMethod.Get, "/api/v2/shares", null, SharesResp.serializer())!!.shares
    suspend fun setShareKeys(publicKey: String, sealedPrivateKey: String) =
        call(HttpMethod.Put, "/api/v2/account/keys", ShareKeys(publicKey, sealedPrivateKey), Account.serializer())!!
    suspend fun userKey(username: String) = call(HttpMethod.Get, "/api/v2/users/${esc(username)}/key", null, UserKey.serializer())!!
    private fun share(id: String) = "/api/v2/shares/${esc(id)}"
    suspend fun createShare(id: String, meta: String, wrappedKey: String) {
        call(HttpMethod.Post, "/api/v2/shares", NewShare(id, meta, wrappedKey), Unit.serializer())
    }
    suspend fun renameShare(id: String, meta: String) { call(HttpMethod.Put, share(id), ShareMetaReq(meta), Unit.serializer()) }
    suspend fun deleteShare(id: String) { call(HttpMethod.Delete, share(id), null, Unit.serializer()) }
    suspend fun addShareMember(id: String, username: String, wrappedKey: String) {
        call(HttpMethod.Put, share(id) + "/members/${esc(username)}", WrappedKeyReq(wrappedKey), Unit.serializer())
    }
    suspend fun removeShareMember(id: String, username: String) {
        call(HttpMethod.Delete, share(id) + "/members/${esc(username)}", null, Unit.serializer())
    }
    suspend fun shareSync(id: String, since: Long) = call(HttpMethod.Get, share(id) + "/sync?since=$since", null, SyncResp.serializer())!!
    suspend fun shareWrite(id: String, writes: List<Write>) = call(HttpMethod.Post, share(id) + "/items", Writes(writes), RevisionResp.serializer())!!.revision

    private fun esc(s: String) = java.net.URLEncoder.encode(s, "UTF-8").replace("+", "%20")

    companion object {
        val client by lazy {
            HttpClient(OkHttp) {
                install(ContentNegotiation) { json(StoriiJson) }
                install(HttpTimeout) { requestTimeoutMillis = 60_000 }
            }
        }
    }
}

@Serializable
private data class RegisterReq(
    val username: String,
    val kdf: Kdf,
    @SerialName("auth_key") val authKey: String,
    @SerialName("wrapped_key") val wrappedKey: String,
    @SerialName("device_name") val deviceName: String,
)
