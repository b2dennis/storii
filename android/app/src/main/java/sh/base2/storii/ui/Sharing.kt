package sh.base2.storii.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.launch
import sh.base2.storii.data.Share
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.vault

/** A question with OK/Cancel, for removing people and deleting or leaving shares. */
private data class Ask(val title: String, val text: String, val ok: String, val run: suspend () -> Unit)

/** Shares: small vaults of their own that several accounts can open. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SharingScreen(nav: NavController) {
    val ctx = LocalContext.current
    val vault = ctx.vault
    val status by vault.status.collectAsState()
    if (status !is VaultStatus.Unlocked) return
    val scope = rememberCoroutineScope()
    var err by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var newName by remember { mutableStateOf("") }
    var ask by remember { mutableStateOf<Ask?>(null) }
    var renaming by remember { mutableStateOf<Share?>(null) }
    // Adding someone: the share, then their key and fingerprint to compare before confirming.
    var adding by remember { mutableStateOf<Share?>(null) }
    var addUser by remember { mutableStateOf("") }
    var found by remember { mutableStateOf<Triple<String, String, String>?>(null) }
    var moving by remember { mutableStateOf<Share?>(null) }

    fun run(block: suspend () -> Unit) {
        busy = true
        err = ""
        scope.launch {
            try {
                block()
            } catch (e: Exception) {
                err = e.message ?: "That didn't work"
            }
            busy = false
        }
    }
    LaunchedEffect(Unit) { runCatching { vault.sync() } }

    Scaffold(topBar = {
        TopAppBar(title = { Text("Sharing") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad ->
        Column(Modifier.padding(pad).padding(horizontal = 16.dp).verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("A share is a small vault of its own. Everyone in it can see and change its secrets; only the owner adds and " +
                "removes people. The server can't read shares either.", style = MaterialTheme.typography.bodyMedium)
            Text("Your key fingerprint", style = MaterialTheme.typography.labelMedium)
            Text(vault.fingerprint().ifEmpty { "not set up (the server may be too old)" }, fontFamily = FontFamily.Monospace)
            Text("When someone adds you, they compare it with what their storii shows.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(newName, { newName = it }, Modifier.weight(1f), label = { Text("New share, e.g. Family") }, singleLine = true)
                Button(enabled = !busy && newName.isNotBlank(), onClick = { run { vault.createShare(newName); newName = "" } },
                    modifier = Modifier.padding(top = 8.dp)) { Text("Create") }
            }
            if (err.isNotEmpty()) Text(err, color = MaterialTheme.colorScheme.error)
            val shares = vault.shares()
            if (shares.isEmpty()) Text("No shares yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
            val secrets = vault.secrets()
            for (s in shares) Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text(s.name, style = MaterialTheme.typography.titleMedium)
                    Text(if (s.mine) "Yours" else "Owned by ${s.owner}", style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        for (m in s.members) InputChip(selected = false, enabled = s.mine && !m.owner,
                            onClick = {
                                ask = Ask("Remove ${m.username}?", "They keep anything they already copied: change those passwords if " +
                                    "that matters.", "Remove") { vault.removeMember(s.id, m.username) }
                            },
                            label = { Text(m.username + if (m.owner) " (owner)" else "") })
                    }
                    val inside = secrets.filter { vault.shareOf(it.id)?.id == s.id }
                    Text("Secrets (${inside.size})", style = MaterialTheme.typography.labelMedium)
                    for (e in inside) Row {
                        Text(e.item.name, Modifier.weight(1f).padding(top = 12.dp))
                        TextButton(enabled = !busy, onClick = { run { vault.move(listOf(e.id), "") } }) { Text("Move to my vault") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(enabled = !busy, onClick = { moving = s }) { Text("Add secrets") }
                        if (s.mine) OutlinedButton(enabled = !busy, onClick = { adding = s; addUser = ""; found = null }) { Text("Add person") }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        if (s.mine) {
                            TextButton(onClick = { renaming = s; newName = s.name }) { Text("Rename") }
                            TextButton(onClick = {
                                ask = Ask("Delete ${s.name}?", "Its secrets are deleted for every member.", "Delete") { vault.deleteShare(s.id) }
                            }) { Text("Delete share", color = MaterialTheme.colorScheme.error) }
                        } else TextButton(onClick = {
                            ask = Ask("Leave ${s.name}?", "Its secrets disappear from your vault.", "Leave") { vault.deleteShare(s.id) }
                        }) { Text("Leave share", color = MaterialTheme.colorScheme.error) }
                    }
                }
            }
        }
    }

    ask?.let { a ->
        AlertDialog(onDismissRequest = { ask = null }, title = { Text(a.title) }, text = { Text(a.text) },
            confirmButton = { TextButton(onClick = { ask = null; run(a.run) }) { Text(a.ok) } },
            dismissButton = { TextButton(onClick = { ask = null }) { Text("Cancel") } })
    }
    renaming?.let { s ->
        AlertDialog(onDismissRequest = { renaming = null }, title = { Text("Rename ${s.name}") },
            text = { OutlinedTextField(newName, { newName = it }, singleLine = true) },
            confirmButton = { TextButton(enabled = newName.isNotBlank(), onClick = { renaming = null; run { vault.renameShare(s.id, newName); newName = "" } }) { Text("Rename") } },
            dismissButton = { TextButton(onClick = { renaming = null; newName = "" }) { Text("Cancel") } })
    }
    adding?.let { s ->
        val f = found
        AlertDialog(onDismissRequest = { adding = null }, title = { Text("Add someone to ${s.name}") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (f == null) OutlinedTextField(addUser, { addUser = it }, label = { Text("Their storii username") }, singleLine = true)
                    else {
                        Text("${f.first}'s key fingerprint:")
                        Text(f.third, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
                        Text("Ask ${f.first} to open Sharing and read theirs. Only add them if it matches.")
                    }
                    if (err.isNotEmpty()) Text(err, color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = {
                if (f == null) TextButton(enabled = !busy && addUser.isNotBlank(), onClick = {
                    run {
                        if (addUser.trim().equals(vault.username, ignoreCase = true)) error("You are already in it.")
                        found = vault.memberKey(addUser)
                    }
                }) { Text("Look up") }
                else TextButton(enabled = !busy, onClick = { adding = null; run { vault.addMember(s.id, f.first, f.second) } }) { Text("It matches, add") }
            },
            dismissButton = { TextButton(onClick = { adding = null }) { Text("Cancel") } })
    }
    moving?.let { s ->
        val personal = vault.secrets().filter { vault.shareOf(it.id) == null }
        AlertDialog(onDismissRequest = { moving = null }, title = { Text("Move into ${s.name}") },
            text = {
                Column(Modifier.verticalScroll(rememberScrollState())) {
                    if (personal.isEmpty()) Text("Everything is shared already.")
                    for (e in personal) TextButton(onClick = { moving = null; run { vault.move(listOf(e.id), s.id) } }) { Text(e.item.name) }
                    Text("Its contexts go along, or get copied when another of your secrets uses them too.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            },
            confirmButton = { TextButton(onClick = { moving = null }) { Text("Done") } })
    }
}

/** On a secret's page: which share it's in, and moving it to another place. */
@Composable
fun ShareLine(id: String) {
    val vault = LocalContext.current.vault
    val scope = rememberCoroutineScope()
    val status by vault.status.collectAsState() // recompose when items move
    if (status !is VaultStatus.Unlocked) return
    val shares = vault.shares()
    val here = vault.shareOf(id)
    var menu by remember { mutableStateOf(false) }
    var err by remember { mutableStateOf("") }
    if (shares.isEmpty() && here == null) return
    Row(Modifier.fillMaxWidth().padding(top = 12.dp)) {
        Text(if (here != null) "Shared in ${here.name}" else "In your vault only", Modifier.weight(1f).padding(top = 12.dp),
            style = MaterialTheme.typography.bodyMedium)
        Box {
            TextButton(onClick = { menu = true }) { Text("Move…") }
            DropdownMenu(menu, { menu = false }) {
                if (here != null) DropdownMenuItem(text = { Text("My vault") }, onClick = {
                    menu = false
                    scope.launch { err = runCatching { vault.move(listOf(id), "") }.exceptionOrNull()?.message.orEmpty() }
                })
                for (s in shares) if (s.id != here?.id) DropdownMenuItem(text = { Text(s.name) }, onClick = {
                    menu = false
                    scope.launch { err = runCatching { vault.move(listOf(id), s.id) }.exceptionOrNull()?.message.orEmpty() }
                })
            }
        }
    }
    if (err.isNotEmpty()) Text(err, color = MaterialTheme.colorScheme.error)
}
