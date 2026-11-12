package sh.base2.storii.ui

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
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
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
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
import androidx.compose.runtime.LaunchedEffect
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
import sh.base2.storii.core.BitwardenImport
import sh.base2.storii.core.OnePasswordImport
import sh.base2.storii.core.Import
import sh.base2.storii.core.OtpImport
import sh.base2.storii.data.Vault
import sh.base2.storii.data.VaultStatus
import sh.base2.storii.vault
import java.util.UUID

private const val MAX_BYTES = 20 shl 20

/** What the import screen shows. */
private sealed interface ImportState {
    data object Start : ImportState
    data object Working : ImportState
    /** [what] names a row: "login", "2FA code" or (Bitwarden, which has all kinds) "item". */
    data class Ready(val uri: Uri, val plan: Import.Plan, val rows: Int, val what: String = "login", val unreadable: List<String> = emptyList()) : ImportState
    data class Done(val uri: Uri, val lines: Import.Plan, val deleted: Boolean?, val what: String = "login") : ImportState
    /** An Authy export: its secrets are encrypted with the Authy backup password. */
    data class AuthyPassword(val uri: Uri, val text: String, val error: String? = null) : ImportState
    data class Failed(val message: String) : ImportState
}

/** Imports a CSV export, from Google Password Manager above all. [shared] is a file shared to storii. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportScreen(nav: NavController, shared: String?) {
    val ctx = LocalContext.current
    val vault = ctx.vault
    val scope = rememberCoroutineScope()
    var state by remember { mutableStateOf<ImportState>(ImportState.Start) }

    fun items() = (vault.status.value as? VaultStatus.Unlocked)?.items ?: error("storii is locked")
    fun newId() = UUID.randomUUID().toString()

    /** 2FA codes: an Authy export (after its password) or otpauth:// links. */
    suspend fun codes(uri: Uri, text: String, password: String?): ImportState = try {
        val parsed = withContext(Dispatchers.Default) { OtpImport.parse(text, password) }
        ImportState.Ready(uri, OtpImport.build(items(), parsed.rows, ::newId), parsed.rows.size, "2FA code", unreadable = parsed.failed)
    } catch (e: OtpImport.NeedPassword) {
        ImportState.AuthyPassword(uri, text)
    } catch (e: OtpImport.WrongPassword) {
        ImportState.AuthyPassword(uri, text, e.message)
    }

    fun load(uri: Uri) {
        state = ImportState.Working
        scope.launch {
            state = runCatching {
                val text = withContext(Dispatchers.IO) { readText(ctx, uri) }
                if (OnePasswordImport.detect(text)) {
                    val op = withContext(Dispatchers.Default) { OnePasswordImport.parse(text) }
                    return@runCatching ImportState.Ready(uri, BitwardenImport.build(items(), op, ::newId), op.count, "item", op.failed)
                }
                if (BitwardenImport.detect(text)) {
                    val bw = withContext(Dispatchers.Default) { BitwardenImport.parse(text) }
                    return@runCatching ImportState.Ready(uri, BitwardenImport.build(items(), bw, ::newId), bw.count, "item", bw.failed)
                }
                if (OtpImport.detect(text) != OtpImport.Kind.LOGINS) return@runCatching codes(uri, text, null)
                val rows = Import.parse(text)
                ImportState.Ready(uri, Import.build(items(), rows, ::newId), rows.size)
            }.getOrElse {
                ImportState.Failed(if (it is Import.NotAnExport || it is OtpImport.Empty || it is BitwardenImport.Encrypted) it.message!! else "Couldn't read that file.")
            }
        }
    }
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> uri?.let(::load) }
    LaunchedEffect(shared) { shared?.let { load(Uri.parse(it)) } }

    Scaffold(topBar = {
        TopAppBar(title = { Text("Import") },
            navigationIcon = { IconButton(onClick = { nav.popBackStack() }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad ->
        Column(Modifier.padding(pad).verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            when (val s = state) {
                ImportState.Start, is ImportState.Failed -> {
                    Text("From Google Password Manager", style = MaterialTheme.typography.titleMedium)
                    Text("1. Open Google Password Manager: in the Settings app search for \"Password Manager\", or open it " +
                        "from Chrome › Settings › Google Password Manager.\n" +
                        "2. Tap Settings (the gear) › Export passwords, and confirm with your screen lock.\n" +
                        "3. Share the file to storii, or save it and choose it below.")
                    Text("Exports from Chrome, Firefox, Bitwarden and 1Password work too. Logins already in storii are " +
                        "skipped, so you can import again later.", style = MaterialTheme.typography.bodySmall)
                    Text("Everything from Bitwarden", style = MaterialTheme.typography.titleMedium)
                    Text("In Bitwarden, open Tools › Export vault and choose the file format \".json\" (not the encrypted " +
                        "one). storii imports its logins, 2FA codes, cards and passkeys.", style = MaterialTheme.typography.bodyMedium)
                    Text("Everything from 1Password", style = MaterialTheme.typography.titleMedium)
                    Text("In the 1Password app, choose File › Export, then the format 1PUX. storii imports its logins, " +
                        "2FA codes and cards (1Password doesn't export passkeys).", style = MaterialTheme.typography.bodyMedium)
                    Text("2FA codes from Authy", style = MaterialTheme.typography.titleMedium)
                    Text("Authy has no export. Ask Twilio for your data instead (a GDPR request, see the storii README): " +
                        "the file you get back holds your 2FA codes, encrypted with your Authy backup password. Choose it " +
                        "below. Lists of otpauth:// links (from Aegis, 2FAS and others) work too.",
                        style = MaterialTheme.typography.bodyMedium)
                    if (s is ImportState.Failed) Text(s.message, color = MaterialTheme.colorScheme.error)
                    Button(onClick = { pick.launch(arrayOf("text/*", "application/csv", "application/json", "application/vnd.ms-excel", "application/zip", "application/octet-stream")) },
                        Modifier.fillMaxWidth()) { Text("Choose export file") }
                }
                ImportState.Working -> CircularProgressIndicator()
                is ImportState.AuthyPassword -> {
                    var pw by remember { mutableStateOf("") }
                    Text("This is an Authy export. Its 2FA codes are encrypted with your Authy backup password (the one " +
                        "Authy asks for when you add a device), not your storii password.")
                    PasswordField(pw, { pw = it }, "Authy backup password")
                    s.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                    Button(onClick = {
                        state = ImportState.Working
                        scope.launch { state = runCatching { codes(s.uri, s.text, pw) }.getOrElse { ImportState.Failed(it.message ?: "Couldn't decrypt.") } }
                    }, Modifier.fillMaxWidth(), enabled = pw.isNotEmpty()) { Text("Decrypt") }
                    OutlinedButton(onClick = { state = ImportState.Start }, Modifier.fillMaxWidth()) { Text("Cancel") }
                }
                is ImportState.Ready -> {
                    val p = s.plan
                    val add = p.count(Import.Action.ADD)
                    val users = p.count(Import.Action.USERNAME)
                    val what = s.what
                    Summary(p, s.rows, what)
                    if (s.unreadable.isNotEmpty()) Text("Couldn't read ${n(s.unreadable.size, what)}: ${s.unreadable.joinToString("; ")}",
                        color = MaterialTheme.colorScheme.error)
                    if (add + users == 0) {
                        Text("Everything in this file is already in storii.")
                        DeleteFile(s.uri) { state = ImportState.Done(s.uri, p, it, s.what) }
                    } else {
                        Button(onClick = {
                            state = ImportState.Working
                            scope.launch {
                                state = runCatching {
                                    vault.write(p.writes.map { (id, it) -> Vault.Change.Put(id, it) })
                                    ImportState.Done(s.uri, p, null, s.what)
                                }.getOrElse { ImportState.Failed("Import failed: ${it.message}") }
                            }
                        }, Modifier.fillMaxWidth()) { Text(if (add > 0) "Import ${n(add, what)}" else "Fill in ${n(users, "username")}") }
                        OutlinedButton(onClick = { state = ImportState.Start }, Modifier.fillMaxWidth()) { Text("Cancel") }
                    }
                    Lines(p)
                }
                is ImportState.Done -> {
                    Text("Imported ${n(s.lines.count(Import.Action.ADD), s.what)}" +
                        (s.lines.count(Import.Action.USERNAME).takeIf { it > 0 }?.let { " and filled in ${n(it, "username")}" } ?: "") + ".")
                    when (s.deleted) {
                        true -> Text("The export file is deleted.")
                        else -> {
                            Text("The export file holds your secrets. Delete it now" +
                                (if (s.deleted == false) ": storii couldn't, so delete it in your Files app." else "."),
                                color = MaterialTheme.colorScheme.error)
                            if (s.deleted == null) DeleteFile(s.uri) { state = s.copy(deleted = it) }
                        }
                    }
                    Button(onClick = { nav.popBackStack(HomeRoute, inclusive = false) }, Modifier.fillMaxWidth()) { Text("Done") }
                }
            }
        }
    }
}

@Composable
private fun Summary(p: Import.Plan, rows: Int, what: String) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text("${n(rows, what)} in the file", style = MaterialTheme.typography.titleMedium)
            Text("${p.count(Import.Action.ADD)} new")
            p.count(Import.Action.USERNAME).takeIf { it > 0 }?.let { Text("${n(it, "username")} filled in (for logins that had none)") }
            Text("${p.count(Import.Action.SKIP)} already in storii")
            p.count(Import.Action.INVALID).takeIf { it > 0 }?.let { Text("$it without a password, left out") }
            p.lines.count { it.differs }.takeIf { it > 0 }?.let {
                Text("${n(it, "login")} with a different password for the same site and username; both are kept, so " +
                    "check which one is current afterwards.",
                    style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun Lines(p: Import.Plan) {
    val shown = p.lines.filter { it.action == Import.Action.ADD || it.action == Import.Action.USERNAME }
    if (shown.isEmpty()) return
    HorizontalDivider()
    shown.forEach { l ->
        Column {
            Text(l.name)
            val what = when {
                l.action == Import.Action.USERNAME -> "fills in the username"
                l.differs -> "new · another password for this login is kept too"
                else -> "new"
            }
            Text(listOf(l.site.takeIf { it.isNotEmpty() && it != l.name }, what).filterNotNull().joinToString("  ·  "),
                style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun DeleteFile(uri: Uri, done: (Boolean) -> Unit) {
    val ctx = LocalContext.current
    OutlinedButton(onClick = {
        done(runCatching { DocumentsContract.deleteDocument(ctx.contentResolver, uri) }.getOrDefault(false))
    }, Modifier.fillMaxWidth()) { Text("Delete the export file") }
}

/** The file as text; for a 1Password .1pux (a zip), its export.data. */
private fun readText(ctx: Context, uri: Uri): String {
    val input = ctx.contentResolver.openInputStream(uri)?.buffered() ?: error("Couldn't open that file.")
    input.mark(4)
    val magic = ByteArray(4).also { b -> input.read(b) }
    input.reset()
    if (magic.contentEquals(byteArrayOf(0x50, 0x4b, 0x03, 0x04))) {
        return input.use { OnePasswordImport.unzip(it, MAX_BYTES) } ?: throw Import.NotAnExport("That zip isn't a 1Password export (.1pux).")
    }
    val out = java.io.ByteArrayOutputStream()
    input.use {
        val buf = ByteArray(64 shl 10)
        while (true) {
            val n = it.read(buf)
            if (n < 0) break
            out.write(buf, 0, n)
            if (out.size() > MAX_BYTES) error("That file is too big for a password export.")
        }
    }
    return out.toString(Charsets.UTF_8.name())
}

private fun n(count: Int, word: String) = "$count $word" + if (count == 1) "" else "s"
