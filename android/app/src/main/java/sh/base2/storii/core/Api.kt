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
)

@Serializable
data class SessionResp(val token: String, val account: Account)

@Serializable
data class RemoteItem(val id: String, val data: String? = null, val deleted: Boolean = false, val revision: Long = 0)

@Serializable
data class SyncResp(val revision: Long, val items: List<RemoteItem>)

@Serializable
data class Write(val id: String, val data: String? = null, val delete: Boolean = false)

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
    suspend fun write(writes: List<Write>) = call(HttpMethod.Post, "/api/v2/items", Writes(writes), RevisionResp.serializer())!!.revision

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
