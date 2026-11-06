package sh.base2.storii.autofill

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.app.slice.Slice
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.graphics.drawable.Icon
import android.os.Build
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.InlinePresentation
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillValue
import android.view.inputmethod.InlineSuggestionsRequest
import android.widget.RemoteViews
import android.widget.inline.InlinePresentationSpec
import androidx.autofill.inline.UiVersions
import androidx.autofill.inline.v1.InlineSuggestionUi
import sh.base2.storii.R
import sh.base2.storii.core.Entry
import sh.base2.storii.core.Item
import sh.base2.storii.core.Totp

/** Builds the datasets and responses the autofill service and its activities hand back to Android. */
class Responses(private val ctx: Context, private val screen: ParsedScreen, private val inline: InlineSuggestionsRequest?) {
    private var inlineIndex = 0

    private fun remote(title: String, sub: String?): RemoteViews = RemoteViews(ctx.packageName, R.layout.autofill_item).apply {
        setTextViewText(R.id.title, title)
        setTextViewText(R.id.subtitle, sub.orEmpty())
        setViewVisibility(R.id.subtitle, if (sub.isNullOrEmpty()) android.view.View.GONE else android.view.View.VISIBLE)
    }

    @SuppressLint("RestrictedApi")
    private fun inlinePresentation(title: String, sub: String?): InlinePresentation? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R || inline == null) return null
        val specs = inline.inlinePresentationSpecs
        if (inlineIndex >= inline.maxSuggestionCount || specs.isEmpty()) return null
        val spec: InlinePresentationSpec = specs[minOf(inlineIndex, specs.size - 1)]
        inlineIndex++
        if (!UiVersions.getVersions(spec.style).contains(UiVersions.INLINE_UI_VERSION_1)) return null
        val content = InlineSuggestionUi.newContentBuilder(attribution())
            .setTitle(title)
            .apply { if (!sub.isNullOrEmpty()) setSubtitle(sub) }
            .setStartIcon(Icon.createWithResource(ctx, R.drawable.ic_key))
            .build()
        val slice: Slice = content.slice
        return InlinePresentation(slice, spec, false)
    }

    private fun attribution(): PendingIntent = PendingIntent.getActivity(
        ctx, 0, Intent(ctx, sh.base2.storii.ui.MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE,
    )

    @Suppress("DEPRECATION")
    private fun dataset(title: String, sub: String?, fill: Dataset.Builder.() -> Unit): Dataset {
        val b = Dataset.Builder(remote(title, sub))
        inlinePresentation(title, sub)?.let { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) b.setInlinePresentation(it) }
        b.fill()
        return b.build()
    }

    /** The dataset that fills one secret into this screen, or null when it has nothing for these fields. */
    @Suppress("DEPRECATION")
    fun datasetFor(e: Entry): Dataset? {
        val it = e.item
        return when (it.type) {
            Item.PASSWORD -> {
                if (screen.username == null && screen.password == null) return null
                dataset(it.name, it.field("username").ifEmpty { null }) {
                    screen.username?.let { id -> setValue(id, AutofillValue.forText(it.field("username"))) }
                    screen.password?.let { id -> setValue(id, AutofillValue.forText(it.field("password"))) }
                }
            }
            Item.TOTP -> {
                val otp = screen.otp ?: return null
                val code = runCatching { Totp.fromFields(it.fields).code() }.getOrNull() ?: return null
                dataset(it.name, "2FA code") { setValue(otp, AutofillValue.forText(code)) }
            }
            else -> null
        }
    }

    /** A dataset that runs an activity first (unlock, or search the whole vault). */
    @Suppress("DEPRECATION")
    fun authDataset(title: String, sub: String?, sender: IntentSender): Dataset = dataset(title, sub) {
        for (id in screen.ids) setValue(id, null)
        setAuthentication(sender)
    }

    fun saveInfo(): SaveInfo? {
        val pw = screen.password ?: return null
        val type = if (screen.username != null) SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME else SaveInfo.SAVE_DATA_TYPE_PASSWORD
        return SaveInfo.Builder(type, arrayOf(pw)).apply {
            screen.username?.let { setOptionalIds(arrayOf(it)) }
        }.build()
    }

    fun response(datasets: List<Dataset>): FillResponse? {
        if (datasets.isEmpty() && saveInfo() == null) return null
        return FillResponse.Builder().apply {
            datasets.forEach { addDataset(it) }
            saveInfo()?.let { setSaveInfo(it) }
        }.build()
    }

    /** Locked vault: one entry that unlocks and then answers the request properly. */
    fun lockedResponse(sender: IntentSender): FillResponse {
        val title = "Unlock storii"
        return FillResponse.Builder().apply {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val p = inlinePresentation(title, null)
                @Suppress("DEPRECATION")
                if (p != null) setAuthentication(screen.ids.toTypedArray(), sender, remote(title, null), p)
                else setAuthentication(screen.ids.toTypedArray(), sender, remote(title, null))
            } else {
                @Suppress("DEPRECATION")
                setAuthentication(screen.ids.toTypedArray(), sender, remote(title, null))
            }
            saveInfo()?.let { setSaveInfo(it) }
        }.build()
    }

}
