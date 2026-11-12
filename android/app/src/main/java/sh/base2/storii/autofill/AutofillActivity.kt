package sh.base2.storii.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.inputmethod.InlineSuggestionsRequest
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Color
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.launch
import sh.base2.storii.BuildConfig
import sh.base2.storii.core.Entry
import sh.base2.storii.core.Item
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.ui.FormPage
import sh.base2.storii.ui.Logo
import sh.base2.storii.ui.StoriiTheme
import sh.base2.storii.ui.TypeBadge
import sh.base2.storii.ui.UnlockPane
import sh.base2.storii.vault

/**
 * What autofill hands off to: unlocking a locked vault (then answering the fill request), picking any secret from the
 * vault (and remembering it for this app or site), or saving a login while the vault is locked.
 */
class AutofillActivity : FragmentActivity() {
    private lateinit var screen: ParsedScreen
    private var inline: InlineSuggestionsRequest? = null
    private lateinit var mode: String

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        mode = intent.getStringExtra(EXTRA_MODE) ?: MODE_PICK
        screen = ParsedScreen(
            packageName = intent.getStringExtra(EXTRA_PACKAGE).orEmpty(),
            webDomain = intent.getStringExtra(EXTRA_DOMAIN),
            username = parcel(EXTRA_USERNAME), password = parcel(EXTRA_PASSWORD), otp = parcel(EXTRA_OTP),
            usernameValue = intent.getStringExtra(EXTRA_USERNAME_VALUE).orEmpty(),
            passwordValue = intent.getStringExtra(EXTRA_PASSWORD_VALUE).orEmpty(),
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) inline = parcel(EXTRA_INLINE)
        setContent { StoriiTheme { Content() } }
    }

    private inline fun <reified T : android.os.Parcelable> parcel(key: String): T? =
        if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(key, T::class.java)
        else @Suppress("DEPRECATION") intent.getParcelableExtra(key)

    private val target: String
        get() = screen.webDomain ?: StoriiAutofillService.appLabel(this, screen.packageName) ?: screen.packageName

    private fun finishWith(result: android.os.Parcelable?) {
        if (result != null) setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, result))
        else setResult(RESULT_CANCELED)
        finish()
    }

    @Composable
    private fun Content() {
        val status by vault.status.collectAsState()
        var picking by remember { mutableStateOf(mode == MODE_PICK) }
        when (val s = status) {
            VaultStatus.NotSetUp -> Page { FormPage { Text("Open storii and log in first.") } }
            // Over the app being filled: just the biometric prompt, or a sheet with the master password.
            is VaultStatus.Locked -> Sheet(onDismiss = { finishWith(null) }) { UnlockPane(this, s.username, s.server, compact = true, onUnlocked = {
                if (mode == MODE_UNLOCK) {
                    val r = StoriiAutofillService.respond(this, screen, inline)
                    // Nothing stored for this app or site yet: go straight to the search.
                    if (!screen.hasCard && vault.forTarget(screen.webDomain, StoriiAutofillService.appPackage(screen)).isEmpty()) picking = true
                    else finishWith(r)
                }
            }) { OutlinedButton(onClick = { finishWith(null) }, modifier = Modifier.fillMaxWidth()) { Text("Cancel") } } }
            is VaultStatus.Unlocked -> when {
                mode == MODE_SAVE -> Page { SaveScreen() }
                picking -> Page { PickScreen() }
                else -> androidx.compose.runtime.LaunchedEffect(Unit) { finishWith(StoriiAutofillService.respond(this@AutofillActivity, screen, inline)) }
            }
        }
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun PickScreen() {
        var query by remember { mutableStateOf("") }
        var rememberIt by remember { mutableStateOf(true) }
        val scope = rememberCoroutineScope()
        val wanted = buildSet {
            if (screen.username != null || screen.password != null) add(Item.PASSWORD)
            if (screen.otp != null) add(Item.TOTP)
            if (screen.hasCard) add(Item.CARD)
        }
        val all = vault.secrets().filter { it.item.type in wanted }
        val shown = all.filter { e ->
            query.isBlank() || listOf(e.item.name, e.item.field("username"), e.item.field("issuer")).any { it.contains(query, true) }
        }
        fun pick(e: Entry) = scope.launch {
            if (rememberIt) runCatching {
                vault.remember(e.id, screen.webDomain, StoriiAutofillService.appPackage(screen),
                    StoriiAutofillService.appLabel(this@AutofillActivity, screen.packageName))
            }
            val ds = Responses(this@AutofillActivity, screen, inline).datasetFor(e)
            // A dataset answers a dataset's authentication; the "Unlock" entry stands for the whole response.
            if (mode == MODE_PICK) finishWith(ds)
            else finishWith(Responses(this@AutofillActivity, screen, inline).response(listOfNotNull(ds)))
        }
        Scaffold(topBar = { TopAppBar(title = { Text("Fill $target") }) }) { pad ->
            Column(Modifier.padding(pad).fillMaxSize()) {
                OutlinedTextField(query, { query = it }, label = { Text("Search") }, singleLine = true,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp))
                Row(Modifier.fillMaxWidth().clickable { rememberIt = !rememberIt }.padding(horizontal = 4.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(rememberIt, { rememberIt = it })
                    Text("Remember for $target")
                }
                LazyColumn(Modifier.fillMaxSize()) {
                    items(shown, key = { it.id }) { e ->
                        Row(Modifier.fillMaxWidth().clickable { pick(e) }.padding(horizontal = 16.dp, vertical = 10.dp),
                            horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
                            TypeBadge(e.item.type)
                            Column {
                                Text(e.item.name, fontWeight = FontWeight.SemiBold)
                                val sub = e.item.field("username").ifEmpty { e.item.field("issuer") }
                                if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }
                    if (shown.isEmpty()) item { Text("Nothing matches.", Modifier.padding(16.dp)) }
                }
            }
        }
    }

    @Composable
    private fun SaveScreen() {
        val scope = rememberCoroutineScope()
        var error by remember { mutableStateOf<String?>(null) }
        FormPage {
            Logo()
            Text("Save this login for $target?", style = MaterialTheme.typography.titleLarge)
            if (screen.usernameValue.isNotEmpty()) Text("as ${screen.usernameValue}")
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(onClick = {
                scope.launch {
                    try {
                        vault.saveLogin(screen.webDomain, StoriiAutofillService.appPackage(screen),
                            StoriiAutofillService.appLabel(this@AutofillActivity, screen.packageName), screen.usernameValue, screen.passwordValue)
                        finish()
                    } catch (e: Exception) {
                        error = e.message
                    }
                }
            }, modifier = Modifier.fillMaxWidth()) { Text("Save") }
            OutlinedButton(onClick = { finish() }, modifier = Modifier.fillMaxWidth()) { Text("Not now") }
        }
    }

    /** A full screen (the activity's window is translucent). */
    @Composable
    private fun Page(content: @Composable () -> Unit) = Surface(Modifier.fillMaxSize()) { content() }

    /** A bottom sheet over the app being filled; tapping outside cancels. */
    @Composable
    private fun Sheet(onDismiss: () -> Unit, content: @Composable () -> Unit) {
        Box(Modifier.fillMaxSize().background(Color.Black.copy(alpha = 0.32f))
            .clickable(interactionSource = null, indication = null, onClick = onDismiss)
            .imePadding(), contentAlignment = Alignment.BottomCenter) {
            Surface(Modifier.widthIn(max = 560.dp).fillMaxWidth().navigationBarsPadding()
                .clickable(interactionSource = null, indication = null) {},
                shape = RoundedCornerShape(topStart = 28.dp, topEnd = 28.dp), tonalElevation = 2.dp) { content() }
        }
    }

    companion object {
        const val MODE_UNLOCK = "unlock"
        const val MODE_PICK = "pick"
        const val MODE_SAVE = "save"
        private const val EXTRA_MODE = "mode"
        private const val EXTRA_PACKAGE = "package"
        private const val EXTRA_DOMAIN = "domain"
        private const val EXTRA_USERNAME = "username"
        private const val EXTRA_PASSWORD = "password"
        private const val EXTRA_OTP = "otp"
        private const val EXTRA_USERNAME_VALUE = "usernameValue"
        private const val EXTRA_PASSWORD_VALUE = "passwordValue"
        private const val EXTRA_INLINE = "inline"
        private var requestCode = 1

        fun sender(ctx: Context, mode: String, screen: ParsedScreen, inline: InlineSuggestionsRequest?): IntentSender {
            val i = Intent(ctx, AutofillActivity::class.java)
                .putExtra(EXTRA_MODE, mode)
                .putExtra(EXTRA_PACKAGE, screen.packageName)
                .putExtra(EXTRA_DOMAIN, screen.webDomain)
                .putExtra(EXTRA_USERNAME, screen.username as AutofillId?)
                .putExtra(EXTRA_PASSWORD, screen.password as AutofillId?)
                .putExtra(EXTRA_OTP, screen.otp as AutofillId?)
            if (mode == MODE_SAVE) {
                i.putExtra(EXTRA_USERNAME_VALUE, screen.usernameValue).putExtra(EXTRA_PASSWORD_VALUE, screen.passwordValue)
            }
            if (inline != null) i.putExtra(EXTRA_INLINE, inline)
            // Each request needs its own PendingIntent, or Android reuses the extras of an older one.
            return PendingIntent.getActivity(ctx, requestCode++, i, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
        }
    }
}
