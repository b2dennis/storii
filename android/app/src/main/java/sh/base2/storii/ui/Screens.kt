package sh.base2.storii.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import sh.base2.storii.core.Entry
import sh.base2.storii.core.Item
import sh.base2.storii.core.Totp
import sh.base2.storii.core.typeLabel
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.vault

/** Ticks once a second, for TOTP codes. */
@Composable
fun rememberNow(): Long {
    val now by produceState(System.currentTimeMillis()) {
        while (true) {
            value = System.currentTimeMillis()
            delay(1000 - value % 1000)
        }
    }
    return now
}

fun formatCode(code: String) = if (code.length == 6) code.take(3) + " " + code.drop(3) else code

@Composable
fun SetupScreen(prefill: Pair<String, String>?) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var register by rememberSaveable { mutableStateOf(false) }
    var server by rememberSaveable { mutableStateOf(prefill?.first ?: "") }
    var username by rememberSaveable { mutableStateOf(prefill?.second ?: "") }
    var password by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    fun submit() {
        error = when {
            server.isBlank() || username.isBlank() || password.isEmpty() -> "Fill in all fields."
            register && password != repeat -> "The passwords don't match."
            register && password.length < 12 -> "Use at least 12 characters."
            else -> null
        }
        if (error != null || busy) return
        busy = true
        scope.launch {
            try {
                ctx.vault.login(server, username.trim(), password, register)
            } catch (e: Exception) {
                error = e.message ?: e.toString()
            } finally {
                busy = false
            }
        }
    }

    FormPage {
        Logo()
        Text(if (register) "Create a storii account" else "Log in to storii", style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold)
        Text("Your master password never leaves this device. Without it nobody, the server included, can read your vault.",
            style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedTextField(server, { server = it }, label = { Text("Server") }, placeholder = { Text("https://storii.example.com") },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri, imeAction = ImeAction.Next, autoCorrectEnabled = false))
        OutlinedTextField(username, { username = it }, label = { Text("Username") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Next, autoCorrectEnabled = false))
        PasswordField(password, { password = it }, "Master password", imeAction = if (register) ImeAction.Next else ImeAction.Go, onDone = ::submit)
        if (register) PasswordField(repeat, { repeat = it }, "Repeat master password", imeAction = ImeAction.Go, onDone = ::submit)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(onClick = ::submit, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            if (busy) {
                CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                Spacer(Modifier.width(10.dp))
                Text("Deriving keys…")
            } else Text(if (register) "Create account" else "Log in")
        }
        TextButton(onClick = { register = !register; error = null }, modifier = Modifier.fillMaxWidth()) {
            Text(if (register) "I already have an account" else "Create an account instead")
        }
    }
}

private val FILTERS = listOf(null to "All", Item.PASSWORD to "Passwords", Item.TOTP to "2FA", Item.API_KEY to "API keys", Item.NOTE to "Notes")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(nav: NavController) {
    val ctx = LocalContext.current
    val vault = ctx.vault
    val status by vault.status.collectAsState()
    val unlocked = status as? VaultStatus.Unlocked ?: return
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableStateOf<String?>(null) }
    var refreshing by remember { mutableStateOf(false) }
    val now = rememberNow()

    val contexts = unlocked.items.filterValues { it.isContext }
    val all = unlocked.items.filter { it.value.isSecret }.map { Entry(it.key, it.value) }.sortedBy { it.item.name.lowercase() }
    val shown = all.filter { e ->
        (filter == null || e.item.type == filter) && (query.isBlank() || buildString {
            append(e.item.name); append(' '); append(e.item.field("username")); append(' '); append(e.item.field("issuer"))
            e.item.contexts.forEach { append(' '); append(contexts[it]?.name.orEmpty()) }
        }.contains(query.trim(), ignoreCase = true))
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("storii") }, actions = {
                IconButton(onClick = { nav.navigate(ContextsRoute) }) { Icon(Icons.Default.Hub, "Contexts") }
                IconButton(onClick = { nav.navigate(SettingsRoute) }) { Icon(Icons.Default.Settings, "Settings") }
                IconButton(onClick = { vault.lock() }) { Icon(Icons.Default.Lock, "Lock") }
            })
        },
        floatingActionButton = { FloatingActionButton(onClick = { nav.navigate(EditRoute()) }) { Icon(Icons.Default.Add, "Add") } },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { pad ->
        PullToRefreshBox(refreshing, onRefresh = {
            refreshing = true
            scope.launch {
                runCatching { vault.sync() }.onFailure { snackbar.showSnackbar("Sync failed: ${it.message}") }
                refreshing = false
            }
        }, modifier = Modifier.padding(pad).fillMaxSize()) {
            LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 88.dp)) {
                item {
                    OutlinedTextField(query, { query = it }, placeholder = { Text("Search secrets and contexts") },
                        leadingIcon = { Icon(Icons.Default.Search, null) }, singleLine = true,
                        modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp))
                    Row(Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        FILTERS.forEach { (t, label) -> FilterChip(filter == t, { filter = t }, label = { Text(label) }) }
                    }
                }
                items(shown, key = { it.id }) { e -> SecretRow(e, contexts, now) { nav.navigate(DetailRoute(e.id)) } }
                if (shown.isEmpty()) item {
                    Text(if (all.isEmpty()) "Your vault is empty. Add a password, 2FA code or API key with +." else "Nothing matches.",
                        Modifier.padding(24.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun SecretRow(e: Entry, contexts: Map<String, Item>, now: Long, onClick: () -> Unit) {
    val ctx = LocalContext.current
    val item = e.item
    val totp = if (item.type == Item.TOTP) runCatching { Totp.fromFields(item.fields) }.getOrNull() else null
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
        TypeBadge(item.type)
        Column(Modifier.weight(1f)) {
            Text(item.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val sub = when (item.type) {
                Item.PASSWORD -> item.field("username")
                Item.TOTP -> listOf(item.field("issuer"), item.field("account")).filter { it.isNotEmpty() }.joinToString(" · ")
                Item.API_KEY -> item.field("key_id")
                else -> item.notes.orEmpty().lineSequence().firstOrNull().orEmpty()
            }
            val ctxNames = item.contexts.mapNotNull { contexts[it]?.name }.joinToString(", ")
            val line = listOf(sub, ctxNames).filter { it.isNotEmpty() }.joinToString("  ·  ")
            if (line.isNotEmpty()) Text(line, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        if (totp != null) {
            Column(horizontalAlignment = Alignment.End) {
                Text(formatCode(totp.code(now)), fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 18.sp,
                    color = MaterialTheme.colorScheme.primary)
                Text("${totp.remaining(now)}s", style = MaterialTheme.typography.labelSmall)
            }
        }
        val value = when (item.type) {
            Item.PASSWORD -> item.field("password")
            Item.API_KEY -> item.field("key")
            Item.TOTP -> totp?.code(now)
            else -> null
        }
        if (!value.isNullOrEmpty()) IconButton(onClick = { copySecret(ctx, typeLabel(item.type), value) }) {
            Icon(Icons.Default.ContentCopy, "Copy")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetailScreen(nav: NavController, id: String) {
    val ctx = LocalContext.current
    val status by ctx.vault.status.collectAsState()
    val items = (status as? VaultStatus.Unlocked)?.items ?: return
    val item = items[id] ?: return run { nav.popBackStack() }
    val now = rememberNow()
    Scaffold(topBar = {
        TopAppBar(title = { Text(item.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            actions = { TextButton(onClick = { nav.navigate(EditRoute(id)) }) { Text("Edit") } })
    }) { pad ->
        Column(Modifier.padding(pad).padding(horizontal = 16.dp).verticalScroll(rememberScrollState())) {
            Text(typeLabel(item.type), style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val f = item.fields
            when (item.type) {
                Item.PASSWORD -> {
                    if (f["username"].orEmpty().isNotEmpty()) FieldRow("Username", f["username"]!!, secret = false)
                    FieldRow("Password", f["password"].orEmpty(), secret = true)
                }
                Item.TOTP -> runCatching { Totp.fromFields(f) }.getOrNull()?.let { t ->
                    val code = t.code(now)
                    Row(Modifier.fillMaxWidth().padding(vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(formatCode(code), fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 34.sp,
                                color = MaterialTheme.colorScheme.primary)
                            LinearProgressIndicator(progress = { t.remaining(now) / t.period.toFloat() }, modifier = Modifier.fillMaxWidth(0.6f))
                        }
                        IconButton(onClick = { copySecret(ctx, "2FA code", code) }) { Icon(Icons.Default.ContentCopy, "Copy") }
                    }
                    if (t.issuer.isNotEmpty()) FieldRow("Issuer", t.issuer, secret = false)
                    if (t.account.isNotEmpty()) FieldRow("Account", t.account, secret = false)
                    FieldRow("Setup key", f["secret"].orEmpty(), secret = true)
                }
                Item.API_KEY -> {
                    if (f["key_id"].orEmpty().isNotEmpty()) FieldRow("Key ID", f["key_id"]!!, secret = false)
                    FieldRow("Key", f["key"].orEmpty(), secret = true)
                }
            }
            val known = setOf("username", "password", "secret", "issuer", "account", "algorithm", "digits", "period", "key", "key_id")
            f.filterKeys { it !in known }.forEach { (k, v) -> FieldRow(k, v, secret = false) }
            item.custom.forEach { FieldRow(it.name, it.value, secret = it.hidden) }
            if (!item.notes.isNullOrEmpty()) {
                Text("Notes", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 12.dp))
                Text(item.notes, Modifier.padding(vertical = 6.dp))
                HorizontalDivider()
            }
            Text("Contexts", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 12.dp, bottom = 4.dp))
            val linked = item.contexts.mapNotNull { cid -> items[cid]?.let { cid to it } }
            if (linked.isEmpty()) Text("Not linked to any app or website. Edit to add one, so autofill offers it.",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                linked.forEach { (cid, c) -> AssistChip(onClick = { nav.navigate(ContextEditRoute(cid)) }, label = { Text(c.name) }) }
            }
            item.updatedAt?.let {
                Text("Updated ${it.replace('T', ' ').removeSuffix("Z")} UTC", style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 16.dp))
            }
        }
    }
}

@Composable
private fun FieldRow(label: String, value: String, secret: Boolean) {
    val ctx = LocalContext.current
    var shown by remember { mutableStateOf(!secret) }
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(if (shown) value else "••••••••••", fontFamily = if (secret && shown) FontFamily.Monospace else null)
        }
        if (secret) IconButton(onClick = { shown = !shown }) {
            Icon(if (shown) Icons.Default.VisibilityOff else Icons.Default.Visibility, if (shown) "Hide" else "Show")
        }
        IconButton(onClick = { copySecret(ctx, label, value, sensitive = secret) }) { Icon(Icons.Default.ContentCopy, "Copy $label") }
    }
    HorizontalDivider()
}
