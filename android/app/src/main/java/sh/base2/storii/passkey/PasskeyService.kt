package sh.base2.storii.passkey

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import sh.base2.storii.core.Item
import sh.base2.storii.vault

/**
 * storii as an Android passkey provider (Credential Manager, Android 14+): apps and browsers ask it to create
 * passkeys and to sign in with them. The work happens in [PasskeyActivity], over the calling app.
 */
class PasskeyService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest || !vault.isSetUp) {
            callback.onError(CreateCredentialUnknownException("storii isn't set up"))
            return
        }
        val account = when (val st = vault.status.value) {
            is sh.base2.storii.data.VaultStatus.Locked -> st.username
            is sh.base2.storii.data.VaultStatus.Unlocked -> st.username
            else -> "storii"
        }
        val entry = CreateEntry.Builder(account, pending(this, PasskeyActivity.MODE_CREATE)).setDescription("Saved in storii, synced to your devices").build()
        callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        callback.onResult(answer(this, request))
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest, cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        callback.onResult(null)
    }

    companion object {
        private var requestCode = 100

        fun pending(ctx: Context, mode: String, itemId: String? = null): PendingIntent {
            val i = Intent(ctx, PasskeyActivity::class.java).putExtra(PasskeyActivity.EXTRA_MODE, mode).putExtra(PasskeyActivity.EXTRA_ID, itemId)
            return PendingIntent.getActivity(ctx, requestCode++, i, PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        }

        /** The passkeys storii has for a request: one entry each, or "Unlock storii" while locked. */
        fun answer(ctx: Context, request: BeginGetCredentialRequest): BeginGetCredentialResponse {
            val options = request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>()
            val vault = ctx.vault
            if (options.isEmpty() || !vault.isSetUp) return BeginGetCredentialResponse()
            if (!vault.isUnlocked) {
                return BeginGetCredentialResponse.Builder()
                    .addAuthenticationAction(AuthenticationAction("Unlock storii", pending(ctx, PasskeyActivity.MODE_UNLOCK))).build()
            }
            val entries = mutableListOf<CredentialEntry>()
            for (opt in options) {
                val req = runCatching { Json.parseToJsonElement(opt.requestJson).jsonObject }.getOrNull() ?: continue
                val rpId = req["rpId"]?.jsonPrimitive?.content ?: continue
                val allow = req["allowCredentials"]?.jsonArray?.mapNotNull { it.jsonObject["id"]?.jsonPrimitive?.content?.trimEnd('=') }.orEmpty()
                for (e in vault.secrets().filter { it.item.type == Item.PASSKEY && it.item.field("rp_id") == rpId }) {
                    if (allow.isNotEmpty() && e.item.field("credential_id") !in allow) continue
                    entries += PublicKeyCredentialEntry.Builder(ctx, e.item.field("user_name").ifEmpty { e.item.name },
                        pending(ctx, PasskeyActivity.MODE_GET, e.id), opt)
                        .setDisplayName(e.item.name).build()
                }
            }
            return BeginGetCredentialResponse.Builder().setCredentialEntries(entries).build()
        }
    }
}
