package sh.base2.storii.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.ui.Modifier
import androidx.core.content.IntentCompat
import androidx.fragment.app.FragmentActivity
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.toRoute
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import sh.base2.storii.BuildConfig
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.vault

@Serializable data object HomeRoute
@Serializable data class DetailRoute(val id: String)
@Serializable data class EditRoute(val id: String? = null, val type: String? = null)
@Serializable data object ContextsRoute
@Serializable data class ContextEditRoute(val id: String? = null)
@Serializable data object SettingsRoute
@Serializable data object ScanRoute
@Serializable data class ImportRoute(val shared: String? = null)

class MainActivity : FragmentActivity() {
    /** A password export shared to storii (from Google Password Manager's "Export passwords"), opened once unlocked. */
    val sharedExport = mutableStateOf<Uri?>(null)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState == null) takeShared(intent)
        enableEdgeToEdge()
        // Keep secrets out of screenshots and the recent-apps preview (debug builds allow them for testing).
        if (!BuildConfig.DEBUG) window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContent { StoriiTheme { Surface { App(this) } } }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        takeShared(intent)
    }

    private fun takeShared(intent: Intent?) {
        if (intent?.action != Intent.ACTION_SEND && intent?.action != Intent.ACTION_VIEW) return
        sharedExport.value = if (intent.action == Intent.ACTION_VIEW) intent.data
            else IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
    }
}

@Composable
private fun App(activity: FragmentActivity) {
    val status by activity.vault.status.collectAsState()
    val scope = rememberCoroutineScope()
    var prefill by remember { mutableStateOf<Pair<String, String>?>(null) }
    when (val s = status) {
        VaultStatus.NotSetUp -> SetupScreen(prefill)
        is VaultStatus.Locked -> if (s.expired) {
            FormPage {
                Logo()
                Text("This device was signed out of ${s.server}: the master password was changed or the session was revoked.")
                OutlinedButton(onClick = {
                    prefill = s.server to s.username
                    scope.launch { activity.vault.logout() }
                }, modifier = Modifier.fillMaxWidth()) { Text("Log in again") }
            }
        } else {
            UnlockPane(activity, s.username, s.server, onUnlocked = { scope.launch { runCatching { activity.vault.sync() } } }) {
                SmallTextButton("Log out of this device") { scope.launch { activity.vault.logout() } }
            }
        }
        is VaultStatus.Unlocked -> VaultNav(activity)
    }
}

@Composable
private fun VaultNav(activity: FragmentActivity) {
    val nav = rememberNavController()
    val shared = (activity as? MainActivity)?.sharedExport
    LaunchedEffect(shared?.value) {
        shared?.value?.let { nav.navigate(ImportRoute(it.toString())); shared.value = null }
    }
    NavHost(nav, startDestination = HomeRoute) {
        composable<HomeRoute> { HomeScreen(nav) }
        composable<DetailRoute> { DetailScreen(nav, it.toRoute<DetailRoute>().id) }
        composable<EditRoute> { val r = it.toRoute<EditRoute>(); EditScreen(nav, r.id, r.type) }
        composable<ContextsRoute> { ContextsScreen(nav) }
        composable<ContextEditRoute> { ContextEditScreen(nav, it.toRoute<ContextEditRoute>().id) }
        composable<SettingsRoute> { SettingsScreen(nav, activity) }
        composable<ScanRoute> { ScanScreen(nav) }
        composable<ImportRoute> { ImportScreen(nav, it.toRoute<ImportRoute>().shared) }
    }
}
