package sh.base2.storii.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import sh.base2.storii.core.Item
import sh.base2.storii.core.PasswordHealth
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.vault

/** Weak and reused passwords, and (when asked) the ones Have I Been Pwned has seen in breaches. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HealthScreen(nav: NavController) {
    val ctx = LocalContext.current
    val status by ctx.vault.status.collectAsState()
    val items = (status as? VaultStatus.Unlocked)?.items ?: return
    val report = remember(items) { PasswordHealth.check(items) }
    // id → times seen, once checked.
    var breached by rememberSaveable { mutableStateOf<Map<String, Int>?>(null) }
    var checking by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()
    Scaffold(topBar = {
        TopAppBar(title = { Text("Password health") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad ->
        LazyColumn(Modifier.padding(pad).fillMaxSize(), contentPadding = PaddingValues(bottom = 24.dp)) {
            fun section(title: String, ids: List<String>, note: (String) -> String? = { null }) {
                item { Header(title) }
                items(ids, key = { "$title/$it" }) { id -> items[id]?.let { HealthRow(it, note(id)) { nav.navigate(DetailRoute(id)) } } }
            }
            val found = breached.orEmpty().entries.sortedByDescending { it.value }
            if (found.isNotEmpty()) section("Found in data breaches — change these first", found.map { it.key }) { "Seen %,d times".format(breached!![it]) }
            if (report.reused.isNotEmpty()) {
                item { Header("Reused passwords") }
                report.reused.forEachIndexed { i, g ->
                    if (i > 0) item { HorizontalDivider(Modifier.padding(horizontal = 16.dp)) }
                    items(g, key = { "reused/$it" }) { id -> items[id]?.let { HealthRow(it, null) { nav.navigate(DetailRoute(id)) } } }
                }
            }
            if (report.weak.isNotEmpty()) section("Weak passwords", report.weak)
            if (found.isEmpty() && report.reused.isEmpty() && report.weak.isEmpty()) item {
                Text("No reused or weak passwords.", Modifier.fillMaxWidth().padding(24.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            item {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedButton(enabled = !checking, onClick = {
                        checking = true
                        error = ""
                        scope.launch {
                            runCatching {
                                val pws = PasswordHealth.passwords(items)
                                val seen = PasswordHealth.pwned(pws.values)
                                breached = pws.mapNotNull { (id, pw) -> seen[pw]?.let { id to it } }.toMap()
                            }.onFailure { error = it.message ?: "The breach check failed." }
                            checking = false
                        }
                    }) {
                        Text(when {
                            checking -> "Checking…"
                            breached == null -> "Check for data breaches"
                            breached!!.isEmpty() -> "None found in breaches · check again"
                            else -> "Check again"
                        })
                    }
                    Text("Asks Have I Been Pwned. Only the first 5 characters of each password’s SHA-1 hash are sent, so neither " +
                        "they nor anyone watching can tell which password was checked.",
                        style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    if (error.isNotEmpty()) Text(error, color = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

@Composable
private fun Header(title: String) {
    Text(title.uppercase(), Modifier.padding(start = 16.dp, top = 16.dp, bottom = 4.dp), style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant)
}

@Composable
private fun HealthRow(item: Item, note: String?, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick).padding(horizontal = 16.dp, vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(14.dp)) {
        TypeBadge(item.type)
        Column(Modifier.weight(1f)) {
            Text(item.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
            val sub = note ?: item.field("username")
            if (sub.isNotEmpty()) Text(sub, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}
