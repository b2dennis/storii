package sh.base2.storii.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import kotlinx.coroutines.launch
import sh.base2.storii.core.typeLabel
import sh.base2.storii.data.Vault
import sh.base2.storii.vault
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val trashTime = DateTimeFormatter.ofPattern("d MMM, HH:mm").withZone(ZoneId.systemDefault())

/** Recently deleted secrets and contexts: restore them, or forget them for good. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrashScreen(nav: NavController) {
    val vault = LocalContext.current.vault
    var items by remember { mutableStateOf<List<Vault.Deleted>?>(null) }
    var days by remember { mutableIntStateOf(30) }
    var error by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var confirmEmpty by remember { mutableStateOf(false) }
    var reload by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(reload) {
        runCatching { vault.trash() }.onSuccess { (list, d) -> items = list; days = d; error = "" }
            .onFailure { error = it.message ?: "Couldn't load the trash" }
    }
    fun run(block: suspend () -> Unit) {
        busy = true
        scope.launch {
            runCatching { block() }.onFailure { error = it.message ?: "That didn't work" }
            busy = false
            reload++
        }
    }
    Scaffold(topBar = {
        TopAppBar(title = { Text("Recently deleted") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            actions = { if (!items.isNullOrEmpty()) TextButton(onClick = { confirmEmpty = true }, enabled = !busy) { Text("Empty") } })
    }) { pad ->
        LazyColumn(Modifier.padding(pad).fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
            item {
                Text("Deleted secrets and contexts are kept for $days days.", style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(16.dp))
                if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(horizontal = 16.dp))
            }
            val list = items
            when {
                list == null -> item { Text("Loading…", Modifier.padding(16.dp)) }
                list.isEmpty() -> item { Text("Nothing deleted recently.", Modifier.padding(16.dp)) }
                else -> items(list, key = { it.id }) { d ->
                    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Column(Modifier.weight(1f)) {
                            Text(d.item.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            val kind = if (d.item.isContext) "Context" else typeLabel(d.item.type)
                            val at = runCatching { trashTime.format(Instant.parse(d.deletedAt)) }.getOrDefault(d.deletedAt)
                            Text("$kind · deleted $at", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        TextButton(onClick = { run { vault.restore(listOf(d)) } }, enabled = !busy) { Text("Restore") }
                    }
                    HorizontalDivider()
                }
            }
        }
    }
    if (confirmEmpty) AlertDialog(
        onDismissRequest = { confirmEmpty = false },
        title = { Text("Empty the trash?") },
        text = { Text("${items?.size ?: 0} deleted item(s) will be gone for good, on every device.") },
        confirmButton = { TextButton(onClick = { confirmEmpty = false; run { vault.emptyTrash(emptyList()) } }) { Text("Empty") } },
        dismissButton = { TextButton(onClick = { confirmEmpty = false }) { Text("Cancel") } },
    )
}
