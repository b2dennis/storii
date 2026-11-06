package sh.base2.storii.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.NavController
import kotlinx.coroutines.launch
import sh.base2.storii.StoriiApp
import sh.base2.storii.data.Biometric
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.vault

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(nav: NavController, activity: FragmentActivity) {
    val ctx = LocalContext.current
    val vault = ctx.vault
    val scope = rememberCoroutineScope()
    val status by vault.status.collectAsState()
    val s = status as? VaultStatus.Unlocked ?: return
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var autofillOn by remember { mutableStateOf(false) }
    var bioOn by remember { mutableStateOf(Biometric.enabled(ctx)) }
    var bioPassword by remember { mutableStateOf<String?>(null) }
    var bioError by remember { mutableStateOf<String?>(null) }
    var lockMinutes by remember { mutableIntStateOf(StoriiApp.lockMinutes(ctx)) }
    var lockMenu by remember { mutableStateOf(false) }
    var confirmLogout by remember { mutableStateOf(false) }

    // Re-check when coming back from the system settings.
    LaunchedEffect(Unit) {
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            autofillOn = ctx.getSystemService(AutofillManager::class.java)?.hasEnabledAutofillServices() == true
        }
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text("Settings") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad ->
        Column(Modifier.padding(pad).verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            Text("Autofill", style = MaterialTheme.typography.titleMedium)
            Text(if (autofillOn) "storii fills logins and 2FA codes in apps and browsers."
                else "Make storii your autofill service to fill logins and 2FA codes in apps and browsers. In Chrome, also choose " +
                    "Settings › Autofill services › Autofill using another service.", style = MaterialTheme.typography.bodyMedium)
            if (!autofillOn) Button(onClick = {
                ctx.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:${ctx.packageName}")))
            }) { Text("Use storii for autofill") }
            HorizontalDivider()

            Text("Unlocking", style = MaterialTheme.typography.titleMedium)
            if (Biometric.available(ctx)) {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Biometric unlock")
                        Text("Fingerprint or face instead of the master password", style = MaterialTheme.typography.bodySmall)
                    }
                    Switch(bioOn, { on ->
                        if (on) bioPassword = "" else { Biometric.forget(ctx); bioOn = false }
                    })
                }
                bioError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            }
            Row(Modifier.fillMaxWidth().clickable { lockMenu = true }, verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text("Lock after")
                    Text(if (lockMinutes == 0) "Never (until the app is killed)" else "$lockMinutes minutes in the background",
                        style = MaterialTheme.typography.bodySmall)
                }
                DropdownMenu(lockMenu, { lockMenu = false }) {
                    listOf(1, 5, 15, 60, 0).forEach { m ->
                        DropdownMenuItem(text = { Text(if (m == 0) "Never" else "$m minutes") }, onClick = {
                            StoriiApp.setLockMinutes(ctx, m)
                            lockMinutes = m
                            lockMenu = false
                        })
                    }
                }
            }
            HorizontalDivider()

            Text("Account", style = MaterialTheme.typography.titleMedium)
            Text("${s.username} on ${s.server}")
            OutlinedButton(onClick = { confirmLogout = true }) { Text("Log out of this device", color = MaterialTheme.colorScheme.error) }
        }
    }

    // Turning biometrics on asks for the master password once, so a picked-up unlocked phone can't enable it silently.
    bioPassword?.let { pw ->
        var value by remember { mutableStateOf(pw) }
        AlertDialog(onDismissRequest = { bioPassword = null }, title = { Text("Master password") },
            text = { PasswordField(value, { value = it }, "Master password") },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        try {
                            val key = vault.unlock(value)
                            bioPassword = null
                            Biometric.enable(activity, key)
                            bioOn = true
                            bioError = null
                        } catch (e: Exception) {
                            bioPassword = null
                            bioError = e.message
                        }
                    }
                }) { Text("Continue") }
            },
            dismissButton = { TextButton(onClick = { bioPassword = null }) { Text("Cancel") } })
    }
    if (confirmLogout) AlertDialog(onDismissRequest = { confirmLogout = false },
        title = { Text("Log out?") }, text = { Text("The local copy of the vault is removed from this device. Your secrets stay on the server.") },
        confirmButton = { TextButton(onClick = { scope.launch { vault.logout() } }) { Text("Log out") } },
        dismissButton = { TextButton(onClick = { confirmLogout = false }) { Text("Cancel") } })
}
