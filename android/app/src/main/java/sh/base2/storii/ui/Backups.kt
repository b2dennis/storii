package sh.base2.storii.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import sh.base2.storii.core.Backup
import sh.base2.storii.vault
import java.time.LocalDate

/** Same rule as the master password: the backup is only as strong as its password. */
private fun weakBackupPassword(pw: String): Boolean {
    val kinds = listOf(Regex("[a-z]"), Regex("[A-Z]"), Regex("[0-9]"), Regex("[^a-zA-Z0-9]")).count { it.containsMatchIn(pw) }
    return pw.codePointCount(0, pw.length) < 12 || kinds < 3
}

/** Saving an encrypted backup file, and restoring one. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BackupsScreen(nav: NavController) {
    val ctx = LocalContext.current
    val vault = ctx.vault
    val scope = rememberCoroutineScope()
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var saveMsg by remember { mutableStateOf("") }
    var saveErr by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    // Restoring: the chosen file's text, its password, and what restoring would do.
    var text by remember { mutableStateOf<String?>(null) }
    var rpw by remember { mutableStateOf("") }
    var plan by remember { mutableStateOf<Backup.Plan?>(null) }
    var restoreMsg by remember { mutableStateOf("") }
    var restoreErr by remember { mutableStateOf("") }

    val create = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        scope.launch {
            try {
                val file = vault.backup(pw)
                withContext(Dispatchers.IO) { ctx.contentResolver.openOutputStream(uri, "wt")!!.use { it.write((file + "\n").toByteArray()) } }
                pw = ""; pw2 = ""
                saveMsg = "Backup saved. Without the backup password it can't be opened."
            } catch (e: Exception) {
                saveErr = e.message ?: "Saving the backup failed"
            }
            busy = false
        }
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        restoreErr = ""; restoreMsg = ""; plan = null; text = null
        scope.launch {
            val t = runCatching {
                withContext(Dispatchers.IO) { ctx.contentResolver.openInputStream(uri)!!.use { it.readBytes().takeIf { b -> b.size <= 50 shl 20 }?.decodeToString() } }
            }.getOrNull()
            if (t == null || !Backup.isBackup(t)) restoreErr = "That isn't a storii backup. Other password managers' exports go through Import."
            else text = t
        }
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text("Backups") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad ->
        Column(Modifier.padding(pad).verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("A backup is one file with all your secrets and contexts, encrypted with a backup password you choose. " +
                "It opens without the storii server or your account, in the apps, the browser extension or the CLI. Keep " +
                "the file somewhere safe and the password somewhere else.", style = MaterialTheme.typography.bodyMedium)
            Text("Save a backup", style = MaterialTheme.typography.titleMedium)
            PasswordField(pw, { pw = it; saveErr = "" }, "Backup password")
            PasswordField(pw2, { pw2 = it; saveErr = "" }, "Repeat it")
            if (saveErr.isNotEmpty()) Text(saveErr, color = MaterialTheme.colorScheme.error)
            if (saveMsg.isNotEmpty()) Text(saveMsg, style = MaterialTheme.typography.bodySmall)
            Button(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
                saveMsg = ""
                saveErr = when {
                    weakBackupPassword(pw) -> "Use at least 12 characters and three of: lowercase, uppercase, digits, symbols."
                    pw != pw2 -> "The passwords don't match."
                    else -> ""
                }
                if (saveErr.isEmpty()) create.launch("storii-backup-${LocalDate.now()}.json")
            }) { Text(if (busy) "Encrypting…" else "Save backup") }

            HorizontalDivider()
            Text("Restore a backup", style = MaterialTheme.typography.titleMedium)
            Text("Adds the backup's items that aren't in storii, exactly as they were backed up. Items storii already " +
                "has are left as they are.", style = MaterialTheme.typography.bodyMedium)
            OutlinedButton(onClick = { pick.launch(arrayOf("application/json", "application/octet-stream", "text/plain")) },
                Modifier.fillMaxWidth()) { Text(if (text == null) "Choose a backup file" else "Choose another file") }
            if (text != null && plan == null) {
                PasswordField(rpw, { rpw = it; restoreErr = "" }, "Backup password")
                Button(enabled = !busy && rpw.isNotEmpty(), modifier = Modifier.fillMaxWidth(), onClick = {
                    busy = true
                    scope.launch {
                        try {
                            plan = vault.planRestore(rpw, text!!)
                        } catch (e: Exception) {
                            restoreErr = e.message ?: "Couldn't open the backup"
                        }
                        busy = false
                    }
                }) { Text(if (busy) "Opening…" else "Open backup") }
            }
            plan?.let { p ->
                Text("${p.add.size} to restore, ${p.skipped} already in storii.", style = MaterialTheme.typography.titleSmall)
                if (p.add.isNotEmpty()) {
                    Text(p.add.take(30).joinToString(", ") { it.second.name } + if (p.add.size > 30) ", …" else "",
                        style = MaterialTheme.typography.bodySmall)
                    Button(enabled = !busy, modifier = Modifier.fillMaxWidth(), onClick = {
                        busy = true
                        scope.launch {
                            try {
                                val n = vault.restoreBackup(p)
                                restoreMsg = "Restored $n item${if (n == 1) "" else "s"}."
                                plan = null; text = null; rpw = ""
                            } catch (e: Exception) {
                                restoreErr = e.message ?: "Restoring failed"
                            }
                            busy = false
                        }
                    }) { Text("Restore ${p.add.size} item${if (p.add.size == 1) "" else "s"}") }
                }
            }
            if (restoreErr.isNotEmpty()) Text(restoreErr, color = MaterialTheme.colorScheme.error)
            if (restoreMsg.isNotEmpty()) Text(restoreMsg)
        }
    }
}
