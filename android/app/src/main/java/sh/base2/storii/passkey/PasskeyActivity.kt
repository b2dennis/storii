package sh.base2.storii.passkey

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialInterruptedException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import sh.base2.storii.BuildConfig
import sh.base2.storii.R
import sh.base2.storii.core.Item
import sh.base2.storii.core.Passkey
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.ui.StoriiTheme
import sh.base2.storii.ui.UnlockPane
import sh.base2.storii.vault
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Creates a passkey, signs in with one, or unlocks storii for the system's passkey sheet; drawn over the calling app. */
class PasskeyActivity : FragmentActivity() {
    private lateinit var mode: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        mode = intent.getStringExtra(EXTRA_MODE) ?: MODE_GET
        setContent { StoriiTheme { Content() } }
    }

    private fun done(result: Intent) {
        setResult(RESULT_OK, result)
        finish()
    }

    private fun cancel(message: String = "Cancelled") {
        val r = Intent()
        when (mode) {
            MODE_CREATE -> PendingIntentHandler.setCreateCredentialException(r, CreateCredentialCancellationException(message))
            MODE_GET -> PendingIntentHandler.setGetCredentialException(r, GetCredentialCancellationException(message))
            else -> return run { setResult(RESULT_CANCELED); finish() }
        }
        done(r)
    }

    private fun fail(message: String) {
        val r = Intent()
        if (mode == MODE_CREATE) PendingIntentHandler.setCreateCredentialException(r, CreateCredentialInterruptedException(message))
        else PendingIntentHandler.setGetCredentialException(r, GetCredentialInterruptedException(message))
        done(r)
    }

    @Composable
    private fun Content() {
        val status by vault.status.collectAsState()
        Sheet(onDismiss = { cancel() }) {
            when (val s = status) {
                VaultStatus.NotSetUp -> Column(Modifier.padding(24.dp)) { Text("Open storii and log in first.") }
                is VaultStatus.Locked -> UnlockPane(this, s.username, s.server, compact = true, onUnlocked = {}) {
                    OutlinedButton(onClick = { cancel() }, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
                }
                is VaultStatus.Unlocked -> when (mode) {
                    MODE_UNLOCK -> LaunchedEffect(Unit) {
                        val begin = PendingIntentHandler.retrieveBeginGetCredentialRequest(intent)
                        if (begin == null) return@LaunchedEffect cancel()
                        done(Intent().also { PendingIntentHandler.setBeginGetCredentialResponse(it, PasskeyService.answer(this@PasskeyActivity, begin)) })
                    }
                    MODE_CREATE -> CreateScreen()
                    else -> LaunchedEffect(Unit) { signIn() }
                }
            }
        }
    }

    @Composable
    private fun CreateScreen() {
        val req = remember { PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent) }
        val call = req?.callingRequest as? CreatePublicKeyCredentialRequest
        val json = remember { call?.let { runCatching { Json.parseToJsonElement(it.requestJson).jsonObject }.getOrNull() } }
        val scope = rememberCoroutineScope()
        var error by remember { mutableStateOf<String?>(null) }
        var busy by remember { mutableStateOf(false) }
        if (req == null || json == null) return LaunchedEffect(Unit) { fail("Not a passkey request") }
        val rp = json["rp"]?.jsonObject
        val rpId = rp?.get("id")?.jsonPrimitive?.content ?: ""
        val user = json["user"]?.jsonObject
        val userName = user?.get("name")?.jsonPrimitive?.content.orEmpty()
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Save a passkey?", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Text("For $rpId" + (if (userName.isNotEmpty()) ", as $userName." else "."))
            Text("storii keeps it with your passwords and syncs it to your other devices.", style = MaterialTheme.typography.bodySmall)
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(enabled = !busy, onClick = {
                busy = true
                scope.launch {
                    try {
                        val origin = origin(this@PasskeyActivity, req.callingAppInfo, rpId) ?: throw IllegalStateException(
                            "This app isn't allowed to use passkeys for $rpId.")
                        val excluded = json["excludeCredentials"]?.jsonArray?.mapNotNull { it.jsonObject["id"]?.jsonPrimitive?.content?.trimEnd('=') }.orEmpty()
                        if (vault.secrets().any { it.item.type == Item.PASSKEY && it.item.field("credential_id") in excluded }) {
                            throw IllegalStateException("storii already has a passkey for this account.")
                        }
                        val created = Passkey.create(rpId, origin, json.str("challenge"), user?.str("id").orEmpty(), userName,
                            user?.str("displayName").orEmpty())
                        val id = vault.put(null, Item(kind = Item.KIND_SECRET, type = Item.PASSKEY,
                            name = rp?.str("name")?.ifEmpty { null } ?: rpId, fields = created.fields))
                        vault.remember(id, rpId, null, null)
                        done(Intent().also { PendingIntentHandler.setCreateCredentialResponse(it, CreatePublicKeyCredentialResponse(created.responseJson)) })
                    } catch (e: Exception) {
                        error = e.message
                        busy = false
                    }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Save in storii") }
            OutlinedButton(onClick = { cancel() }, modifier = Modifier.fillMaxWidth()) { Text("Cancel") }
        }
    }

    private suspend fun signIn() {
        val req = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent) ?: return fail("Not a passkey request")
        val item = intent.getStringExtra(EXTRA_ID)?.let { vault.get(it) }?.takeIf { it.type == Item.PASSKEY } ?: return fail("That passkey is gone")
        val option = req.credentialOptions.filterIsInstance<GetPublicKeyCredentialOption>().firstOrNull() ?: return fail("Not a passkey request")
        val json = runCatching { Json.parseToJsonElement(option.requestJson).jsonObject }.getOrNull() ?: return fail("Bad request")
        val rpId = item.field("rp_id")
        val origin = origin(this, req.callingAppInfo, rpId) ?: return fail("This app isn't allowed to use passkeys for $rpId.")
        val a = Passkey.assert(item.fields, origin, json.str("challenge"), option.clientDataHash)
        done(Intent().also { PendingIntentHandler.setGetCredentialResponse(it, GetCredentialResponse(PublicKeyCredential(a.json))) })
    }

    @Composable
    private fun Sheet(onDismiss: () -> Unit, content: @Composable () -> Unit) {
        Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.32f))
            .clickable(interactionSource = null, indication = null, onClick = onDismiss).imePadding(), contentAlignment = Alignment.BottomCenter) {
            Surface(Modifier.widthIn(max = 560.dp).fillMaxWidth().navigationBarsPadding().clickable(interactionSource = null, indication = null) {},
                shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp), tonalElevation = 2.dp) { content() }
        }
    }

    companion object {
        const val EXTRA_MODE = "mode"
        const val EXTRA_ID = "id"
        const val MODE_CREATE = "create"
        const val MODE_GET = "get"
        const val MODE_UNLOCK = "unlock"

        private fun JsonObject.str(k: String) = this[k]?.jsonPrimitive?.content.orEmpty()

        /**
         * The origin a request comes from: a browser on Google's list of privileged browsers names the web origin
         * (which must fit the rpId); any other app must be listed in the site's Digital Asset Links for passkeys.
         */
        suspend fun origin(ctx: Context, app: CallingAppInfo, rpId: String): String? {
            val allowlist = ctx.resources.openRawResource(R.raw.privileged_browsers).bufferedReader().use { it.readText() }
            val web = runCatching { app.getOrigin(allowlist) }.getOrNull()
            if (web != null) return web.trimEnd('/').takeIf { Passkey.rpIdAllowed(rpId, it) }
            if (app.isOriginPopulated()) return null // a browser we don't know: don't trust its claims
            val certs = app.signingInfo.apkContentsSigners.map { MessageDigest.getInstance("SHA-256").digest(it.toByteArray()) }
            val fingerprints = certs.map { c -> c.joinToString(":") { "%02X".format(it) } }
            val links = withContext(Dispatchers.IO) {
                runCatching {
                    val c = URL("https://$rpId/.well-known/assetlinks.json").openConnection() as HttpURLConnection
                    c.connectTimeout = 8000; c.readTimeout = 8000; c.instanceFollowRedirects = false
                    c.inputStream.bufferedReader().use { it.readText() }
                }.getOrNull()
            } ?: return null
            val ok = runCatching {
                Json.parseToJsonElement(links).jsonArray.any { s ->
                    val o = s.jsonObject
                    val relations = o["relation"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty()
                    val t = o["target"]?.jsonObject ?: return@any false
                    "delegate_permission/common.get_login_creds" in relations && t.str("namespace") == "android_app" &&
                        t.str("package_name") == app.packageName &&
                        t["sha256_cert_fingerprints"]?.jsonArray?.any { f -> f.jsonPrimitive.content.uppercase() in fingerprints } == true
                }
            }.getOrDefault(false)
            return if (ok) "android:apk-key-hash:" + Passkey.b64u(certs.first()) else null
        }
    }
}
