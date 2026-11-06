package sh.base2.storii.ui

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.launch
import sh.base2.storii.core.Entry
import sh.base2.storii.core.Item
import sh.base2.storii.core.typeLabel
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.vault

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContextsScreen(nav: NavController) {
    val ctx = LocalContext.current
    val status by ctx.vault.status.collectAsState()
    val items = (status as? VaultStatus.Unlocked)?.items ?: return
    val contexts = items.filter { it.value.isContext }.map { Entry(it.key, it.value) }.sortedBy { it.item.name.lowercase() }
    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Contexts") },
                navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
        },
        floatingActionButton = { FloatingActionButton(onClick = { nav.navigate(ContextEditRoute()) }) { Icon(Icons.Default.Add, "New context") } },
    ) { pad ->
        LazyColumn(Modifier.padding(pad).fillMaxSize(), contentPadding = PaddingValues(bottom = 88.dp)) {
            item {
                Text("A context is an app or website. Every secret in it is offered for autofill there, and one secret can belong to several.",
                    Modifier.padding(16.dp), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            items(contexts, key = { it.id }) { e ->
                val n = items.values.count { it.isSecret && e.id in it.contexts }
                Row(Modifier.fillMaxWidth().clickable { nav.navigate(ContextEditRoute(e.id)) }.padding(horizontal = 16.dp, vertical = 10.dp),
                    horizontalArrangement = Arrangement.spacedBy(14.dp), verticalAlignment = Alignment.CenterVertically) {
                    TypeBadge(e.item.contextType)
                    Column(Modifier.weight(1f)) {
                        Text(e.item.name, fontWeight = FontWeight.SemiBold)
                        Text((e.item.urls + e.item.androidPackages).joinToString(", ").ifEmpty { "No URLs or apps" },
                            style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                    Text("$n", style = MaterialTheme.typography.labelLarge)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContextEditScreen(nav: NavController, id: String?) {
    val ctx = LocalContext.current
    val vault = ctx.vault
    val existing = id?.let { vault.get(it) }
    val scope = rememberCoroutineScope()
    var name by rememberSaveable { mutableStateOf(existing?.name.orEmpty()) }
    var type by rememberSaveable { mutableStateOf(existing?.contextType ?: "website") }
    var urls by rememberSaveable { mutableStateOf(existing?.urls.orEmpty().joinToString("\n")) }
    var apps by rememberSaveable { mutableStateOf(existing?.androidPackages.orEmpty().joinToString("\n")) }
    var pickApp by remember { mutableStateOf(false) }
    var confirmDelete by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val linked = id?.let { cid -> vault.secrets().filter { cid in it.item.contexts } }.orEmpty()

    fun save() {
        if (name.isBlank()) {
            error = "Give it a name."
            return
        }
        val lines = { s: String -> s.lines().map { it.trim() }.filter { it.isNotEmpty() } }
        val item = (existing ?: Item(kind = Item.KIND_CONTEXT, name = name)).copy(name = name.trim(), contextType = type,
            urls = lines(urls), androidPackages = lines(apps))
        scope.launch {
            runCatching { vault.put(id, item) }.onSuccess { nav.popBackStack() }.onFailure { error = it.message }
        }
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text(if (existing == null) "New context" else existing.name) },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            actions = { TextButton(onClick = ::save) { Text("Save") } })
    }) { pad ->
        Column(Modifier.padding(pad).imePadding().verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            val types = listOf("website", "app", "other")
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                types.forEachIndexed { i, t ->
                    SegmentedButton(type == t, { type = t }, SegmentedButtonDefaults.itemShape(i, types.size)) { Text(t.replaceFirstChar { it.uppercase() }) }
                }
            }
            OutlinedTextField(urls, { urls = it }, label = { Text("Websites, one per line") }, placeholder = { Text("https://github.com") },
                minLines = 2, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(apps, { apps = it }, label = { Text("Android apps (package names), one per line") },
                placeholder = { Text("com.github.android") }, minLines = 2, modifier = Modifier.fillMaxWidth())
            OutlinedButton(onClick = { pickApp = true }) {
                Icon(Icons.Default.Apps, null)
                Text("  Add an installed app")
            }
            if (linked.isNotEmpty()) {
                Text("Secrets in this context", style = MaterialTheme.typography.titleSmall)
                linked.forEach { e -> Text("${e.item.name}  ·  ${typeLabel(e.item.type)}", Modifier.clickable { nav.navigate(DetailRoute(e.id)) }) }
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (existing != null) OutlinedButton(onClick = { confirmDelete = true }, modifier = Modifier.fillMaxWidth()) {
                Text("Delete context", color = MaterialTheme.colorScheme.error)
            }
        }
    }

    if (pickApp) AppPicker(onDismiss = { pickApp = false }) { pkg, label ->
        apps = (apps.lines().filter { it.isNotBlank() } + pkg).distinct().joinToString("\n")
        if (name.isBlank()) name = label
        if (urls.isBlank()) type = "app"
        pickApp = false
    }
    if (confirmDelete) AlertDialog(onDismissRequest = { confirmDelete = false },
        title = { Text("Delete ${existing?.name}?") }, text = { Text("Its secrets are kept, they just aren't linked to it any more.") },
        confirmButton = { TextButton(onClick = { scope.launch { vault.delete(listOf(id!!)); nav.popBackStack() } }) { Text("Delete") } },
        dismissButton = { TextButton(onClick = { confirmDelete = false }) { Text("Cancel") } })
}

/** Launchable apps on this device, to pick a package name without typing it. */
@Composable
private fun AppPicker(onDismiss: () -> Unit, onPick: (String, String) -> Unit) {
    val ctx = LocalContext.current
    var query by remember { mutableStateOf("") }
    val apps = remember {
        val pm = ctx.packageManager
        pm.queryIntentActivities(Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER), 0)
            .map { it.activityInfo.packageName to it.loadLabel(pm).toString() }
            .filter { it.first != ctx.packageName }.distinctBy { it.first }.sortedBy { it.second.lowercase() }
    }
    AlertDialog(onDismissRequest = onDismiss, title = { Text("Pick an app") }, text = {
        Column {
            OutlinedTextField(query, { query = it }, label = { Text("Search") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            LazyColumn(Modifier.heightIn(max = 360.dp)) {
                items(apps.filter { query.isBlank() || it.second.contains(query, true) || it.first.contains(query, true) }) { (pkg, label) ->
                    Column(Modifier.fillMaxWidth().clickable { onPick(pkg, label) }.padding(vertical = 8.dp)) {
                        Text(label)
                        Text(pkg, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }, confirmButton = { TextButton(onClick = onDismiss) { Text("Cancel") } })
}
