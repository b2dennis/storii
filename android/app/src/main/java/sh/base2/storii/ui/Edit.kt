package sh.base2.storii.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Casino
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
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
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.launch
import sh.base2.storii.core.Item
import sh.base2.storii.core.Match
import sh.base2.storii.core.Totp
import sh.base2.storii.core.typeLabel
import sh.base2.storii.data.Vault
import sh.base2.storii.vault
import java.security.SecureRandom
import java.util.UUID

fun generatePassword(n: Int = 20): String {
    val sets = listOf("abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*.()")
    val all = sets.joinToString("")
    val r = SecureRandom()
    while (true) {
        val p = String(CharArray(n) { all[r.nextInt(all.length)] })
        if (sets.all { s -> p.any { it in s } }) return p
    }
}

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun EditScreen(nav: NavController, id: String?, initialType: String?) {
    val ctx = LocalContext.current
    val vault = ctx.vault
    val existing = id?.let { vault.get(it) }
    val scope = rememberCoroutineScope()

    var type by rememberSaveable { mutableStateOf(existing?.type ?: initialType ?: Item.PASSWORD) }
    var name by rememberSaveable { mutableStateOf(existing?.name.orEmpty()) }
    var username by rememberSaveable { mutableStateOf(existing?.field("username").orEmpty()) }
    var password by rememberSaveable { mutableStateOf(existing?.field("password").orEmpty()) }
    var totpInput by rememberSaveable { mutableStateOf(existing?.field("secret").orEmpty()) }
    var issuer by rememberSaveable { mutableStateOf(existing?.field("issuer").orEmpty()) }
    var account by rememberSaveable { mutableStateOf(existing?.field("account").orEmpty()) }
    var key by rememberSaveable { mutableStateOf(existing?.field("key").orEmpty()) }
    var keyId by rememberSaveable { mutableStateOf(existing?.field("key_id").orEmpty()) }
    var notes by rememberSaveable { mutableStateOf(existing?.notes.orEmpty()) }
    val contexts = remember { mutableStateListOf<String>().apply { addAll(existing?.contexts.orEmpty()) } }
    // New contexts made here, saved together with the secret.
    val newContexts = remember { mutableStateListOf<Pair<String, Item>>() }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var menu by remember { mutableStateOf(false) }
    var newCtxDialog by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }

    // A scanned QR code comes back through the back stack.
    val scanned by (nav.currentBackStackEntry?.savedStateHandle?.getStateFlow("otpauth", "")
        ?: kotlinx.coroutines.flow.MutableStateFlow("")).collectAsState()
    LaunchedEffect(scanned) {
        if (scanned.isNotEmpty()) {
            totpInput = scanned
            runCatching { Totp.parseUri(scanned) }.getOrNull()?.let { t ->
                if (issuer.isEmpty()) issuer = t.issuer
                if (account.isEmpty()) account = t.account
                if (name.isEmpty()) name = t.issuer.ifEmpty { t.account }
            }
            nav.currentBackStackEntry?.savedStateHandle?.set("otpauth", "")
        }
    }

    val allContexts = vault.contexts().associate { it.id to it.item } + newContexts.toMap()

    fun save() {
        val fields: Map<String, String> = when (type) {
            Item.PASSWORD -> mapOf("username" to username, "password" to password)
            Item.TOTP -> try {
                val raw = totpInput.trim()
                var t = if (raw.startsWith("otpauth://", true)) Totp.parseUri(raw) else Totp.fromFields(mapOf("secret" to raw))
                if (issuer.isNotEmpty()) t = t.copy(issuer = issuer)
                if (account.isNotEmpty()) t = t.copy(account = account)
                if (name.isBlank()) name = t.issuer.ifEmpty { t.account }
                // Keep algorithm/digits/period of an existing secret when only the label changed.
                if (!raw.startsWith("otpauth://", true) && existing != null) existing.fields + t.fields() else t.fields()
            } catch (e: Exception) {
                error = e.message
                return
            }
            Item.API_KEY -> mapOf("key" to key, "key_id" to keyId)
            else -> emptyMap()
        }.filterValues { it.isNotEmpty() }
        if (name.isBlank()) {
            error = "Give it a name."
            return
        }
        val base = existing ?: Item(kind = Item.KIND_SECRET, name = name)
        val item = base.copy(type = type, name = name.trim(), fields = (existing?.fields.orEmpty() - knownFields) + fields,
            contexts = contexts.toList(), notes = notes.ifEmpty { null })
        busy = true
        scope.launch {
            try {
                val changes = newContexts.filter { it.first in contexts }.map { Vault.Change.Put(it.first, it.second) } +
                    Vault.Change.Put(id, item)
                val ids = vault.write(changes)
                nav.popBackStack()
                if (id == null) nav.navigate(DetailRoute(ids.last()))
            } catch (e: Exception) {
                error = e.message
            } finally {
                busy = false
            }
        }
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text(if (existing == null) "New secret" else "Edit") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            actions = { TextButton(onClick = ::save, enabled = !busy) { Text("Save") } })
    }) { pad ->
        Column(Modifier.padding(pad).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (existing == null) {
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    Item.TYPES.forEachIndexed { i, t ->
                        SegmentedButton(type == t, { type = t }, SegmentedButtonDefaults.itemShape(i, Item.TYPES.size)) {
                            Text(typeLabel(t).replace(" code", ""), maxLines = 1)
                        }
                    }
                }
            }
            OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            when (type) {
                Item.PASSWORD -> {
                    OutlinedTextField(username, { username = it }, label = { Text("Username or email") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, autoCorrectEnabled = false))
                    PasswordField(password, { password = it }, "Password", trailing = {
                        IconButton(onClick = { password = generatePassword() }) { Icon(Icons.Default.Casino, "Generate") }
                    })
                }
                Item.TOTP -> {
                    OutlinedTextField(totpInput, { totpInput = it }, label = { Text("Setup key or otpauth:// link") }, singleLine = true,
                        modifier = Modifier.fillMaxWidth(), keyboardOptions = KeyboardOptions(autoCorrectEnabled = false),
                        trailingIcon = { IconButton(onClick = { nav.navigate(ScanRoute) }) { Icon(Icons.Default.QrCodeScanner, "Scan QR code") } })
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(issuer, { issuer = it }, label = { Text("Issuer") }, singleLine = true, modifier = Modifier.weight(1f))
                        OutlinedTextField(account, { account = it }, label = { Text("Account") }, singleLine = true, modifier = Modifier.weight(1f))
                    }
                    val preview = runCatching {
                        val raw = totpInput.trim()
                        if (raw.isEmpty()) null
                        else (if (raw.startsWith("otpauth://", true)) Totp.parseUri(raw) else Totp.fromFields(mapOf("secret" to raw))).code()
                    }
                    Text(preview.fold({ it?.let { c -> "Current code: ${formatCode(c)}" } ?: "Scan the QR code or type the setup key the site shows." },
                        { it.message ?: "Invalid" }), style = MaterialTheme.typography.bodySmall)
                }
                Item.API_KEY -> {
                    PasswordField(key, { key = it }, "Key")
                    OutlinedTextField(keyId, { keyId = it }, label = { Text("Key ID (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                }
            }
            OutlinedTextField(notes, { notes = it }, label = { Text(if (type == Item.NOTE) "Note" else "Notes") },
                minLines = if (type == Item.NOTE) 6 else 2, modifier = Modifier.fillMaxWidth())

            Text("Contexts", style = MaterialTheme.typography.titleSmall)
            Text("The apps and websites this belongs to. Autofill offers it there.", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                contexts.forEach { cid ->
                    InputChip(selected = false, onClick = { contexts.remove(cid) }, label = { Text(allContexts[cid]?.name ?: "?") },
                        trailingIcon = { Icon(Icons.Default.Close, "Remove") })
                }
                Box {
                    AssistChip(onClick = { menu = true }, label = { Text("Add context") }, leadingIcon = { Icon(Icons.Default.Add, null) })
                    DropdownMenu(menu, { menu = false }) {
                        allContexts.filterKeys { it !in contexts }.toList().sortedBy { it.second.name.lowercase() }.forEach { (cid, c) ->
                            DropdownMenuItem(text = { Text(c.name) }, onClick = { contexts.add(cid); menu = false })
                        }
                        DropdownMenuItem(text = { Text("New context…") }, onClick = { menu = false; newCtxDialog = true })
                    }
                }
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (existing != null) OutlinedButton(onClick = { confirmDelete = true }, modifier = Modifier.fillMaxWidth()) {
                Text("Delete", color = MaterialTheme.colorScheme.error)
            }
        }
    }

    if (newCtxDialog) NewContextDialog(onDismiss = { newCtxDialog = false }) { item ->
        val cid = UUID.randomUUID().toString()
        newContexts.add(cid to item)
        contexts.add(cid)
        newCtxDialog = false
    }
    if (confirmDelete) AlertDialog(onDismissRequest = { confirmDelete = false },
        title = { Text("Delete ${existing?.name}?") },
        confirmButton = {
            TextButton(onClick = {
                scope.launch {
                    vault.delete(listOf(id!!))
                    nav.popBackStack(HomeRoute, inclusive = false)
                }
            }) { Text("Delete") }
        },
        dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } })
}

private val knownFields = setOf("username", "password", "secret", "issuer", "account", "key", "key_id")

/** Quick context: a website URL or an Android package name. */
@Composable
fun NewContextDialog(onDismiss: () -> Unit, onCreate: (Item) -> Unit) {
    var name by remember { mutableStateOf("") }
    var target by remember { mutableStateOf("") }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("New context") }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(target, { target = it }, label = { Text("Website or app package") },
                placeholder = { Text("github.com or com.github.android") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, autoCorrectEnabled = false))
            OutlinedTextField(name, { name = it }, label = { Text("Name (optional)") }, singleLine = true)
        }
    }, confirmButton = {
        TextButton(enabled = target.isNotBlank(), onClick = {
            val t = target.trim()
            // Package names have dots but no slashes and don't end in a TLD-like web host; anything with :// is a URL.
            val isApp = !t.contains("://") && Regex("^[a-zA-Z][\\w]*(\\.[a-zA-Z][\\w]*){2,}$").matches(t) && !t.startsWith("www.")
            onCreate(if (isApp) Item(kind = Item.KIND_CONTEXT, name = name.ifBlank { t }, contextType = "app", androidPackages = listOf(t))
            else Item(kind = Item.KIND_CONTEXT, name = name.ifBlank { Match.host(t) }, contextType = "website",
                urls = listOf(if (t.contains("://")) t else "https://${Match.host(t)}")))
        }) { Text("Add") }
    }, dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}
