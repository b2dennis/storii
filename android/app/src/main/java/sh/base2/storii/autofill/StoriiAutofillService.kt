package sh.base2.storii.autofill

import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.SaveCallback
import android.service.autofill.SaveRequest
import android.util.Log
import kotlinx.coroutines.launch
import sh.base2.storii.StoriiApp
import sh.base2.storii.vault

/**
 * Offers the secrets whose contexts match the app (package name) or, in browsers, the website (web domain). Unlocking,
 * searching the whole vault and saving go through [AutofillActivity].
 */
class StoriiAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        val screen = Parser.parse(request.fillContexts.last().structure)
        if (screen.isEmpty || screen.packageName == packageName || !vault.isSetUp) {
            callback.onSuccess(null)
            return
        }
        (application as StoriiApp).checkLock()
        val inline = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) request.inlineSuggestionsRequest else null
        val r = Responses(this, screen, inline)
        if (!vault.isUnlocked) {
            callback.onSuccess(r.lockedResponse(AutofillActivity.sender(this, AutofillActivity.MODE_UNLOCK, screen, inline)))
            return
        }
        callback.onSuccess(respond(this, screen, inline))
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val screen = Parser.parse(request.fillContexts.last().structure)
        if (screen.savedPassword.isEmpty() || screen.packageName == packageName || !vault.isSetUp) {
            callback.onSuccess()
            return
        }
        if (vault.isUnlocked) {
            val label = appLabel(this, screen.packageName)
            val vault = vault
            (application as StoriiApp).scope.launch {
                runCatching { vault.saveLogin(screen.webDomain, appPackage(screen), label, screen.usernameValue, screen.savedPassword,
                    changed = screen.newPasswordValue.isNotEmpty(), current = screen.passwordValue) }
                    .onFailure { Log.w("storii", "save failed", it) }
            }
            callback.onSuccess()
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            callback.onSuccess(AutofillActivity.sender(this, AutofillActivity.MODE_SAVE, screen, null))
        } else {
            callback.onSuccess()
        }
    }

    companion object {
        /** In a browser the web domain decides; the browser's own package must never match an app context. */
        fun appPackage(screen: ParsedScreen) = screen.packageName.takeIf { screen.webDomain.isNullOrBlank() }

        fun appLabel(ctx: android.content.Context, pkg: String): String? = runCatching {
            ctx.packageManager.getApplicationLabel(ctx.packageManager.getApplicationInfo(pkg, 0)).toString()
        }.getOrNull()

        /** The unlocked answer: matching secrets first, then "Search storii…" for everything else. */
        fun respond(ctx: android.content.Context, screen: ParsedScreen, inline: android.view.inputmethod.InlineSuggestionsRequest?) =
            Responses(ctx, screen, inline).let { r ->
                // Cards belong to no site: on a card form, all of them are offered.
                val cards = if (screen.hasCard) ctx.vault.secrets().filter { it.item.type == sh.base2.storii.core.Item.CARD } else emptyList()
                val matches = (cards + ctx.vault.forTarget(screen.webDomain, appPackage(screen))).mapNotNull { r.datasetFor(it) }
                r.response(matches + listOfNotNull(r.suggestion()) + r.authDataset("Search storii…", screen.webDomain ?: appLabel(ctx, screen.packageName),
                    AutofillActivity.sender(ctx, AutofillActivity.MODE_PICK, screen, inline)))
            }
    }
}
