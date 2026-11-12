package sh.base2.storii.ui

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import sh.base2.storii.core.Item
import sh.base2.storii.data.Biometric
import sh.base2.storii.data.BiometricCancelled
import sh.base2.storii.vault

private val clipScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

/** Copies marked as sensitive (hidden from the clipboard preview) and cleared again after 45 seconds. */
fun copySecret(ctx: Context, label: String, value: String, sensitive: Boolean = true) {
    val cm = ctx.getSystemService(ClipboardManager::class.java)
    val clip = ClipData.newPlainText(label, value)
    if (sensitive) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
        }
    }
    cm.setPrimaryClip(clip)
    if (Build.VERSION.SDK_INT < 33) Toast.makeText(ctx, "$label copied", Toast.LENGTH_SHORT).show()
    if (sensitive) clipScope.launch {
        delay(45_000)
        val cur = runCatching { cm.primaryClip?.getItemAt(0)?.text?.toString() }.getOrNull()
        if (cur == value) {
            if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip() else cm.setPrimaryClip(ClipData.newPlainText("", ""))
        }
    }
}

@Composable
fun PasswordField(
    value: String,
    onChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    imeAction: ImeAction = ImeAction.Next,
    onDone: () -> Unit = {},
    trailing: @Composable (() -> Unit)? = null,
) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = value, onValueChange = onChange, label = { Text(label) }, singleLine = true, modifier = modifier.fillMaxWidth(),
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = imeAction, autoCorrectEnabled = false),
        keyboardActions = KeyboardActions(onDone = { onDone() }, onGo = { onDone() }),
        trailingIcon = {
            androidx.compose.foundation.layout.Row {
                trailing?.invoke()
                IconButton(onClick = { visible = !visible }) {
                    Icon(if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility, if (visible) "Hide" else "Show")
                }
            }
        },
    )
}

/** Centered column for the setup and unlock screens. */
@Composable
fun FormPage(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxSize().imePadding().verticalScroll(rememberScrollState()), contentAlignment = Alignment.TopCenter) {
        Column(Modifier.widthIn(max = 480.dp).fillMaxWidth().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Spacer(Modifier.height(32.dp))
            content()
        }
    }
}

@Composable
fun Logo() {
    Box(Modifier.size(64.dp).clip(RoundedCornerShape(18.dp)).background(MaterialTheme.colorScheme.primary), contentAlignment = Alignment.Center) {
        Icon(androidx.compose.ui.res.painterResource(sh.base2.storii.R.drawable.ic_key), null, tint = MaterialTheme.colorScheme.onPrimary,
            modifier = Modifier.size(34.dp))
    }
}

/**
 * Master password or biometric unlock. Biometrics are offered right away when enabled. [onUnlocked] runs once the vault
 * is open.
 */
@Composable
fun UnlockPane(activity: FragmentActivity, username: String, server: String, onUnlocked: () -> Unit, compact: Boolean = false,
               extra: @Composable () -> Unit = {}) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var password by rememberSaveable { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val bio = remember { Biometric.enabled(ctx) && Biometric.available(ctx) }
    val focus = remember { FocusRequester() }
    // In the compact (autofill) form, only the system's biometric prompt shows until it's cancelled.
    var formShown by remember { mutableStateOf(!(compact && bio)) }

    fun biometric() = scope.launch {
        try {
            val key = Biometric.unlock(activity)
            if (key == null) {
                error = "Biometrics changed. Unlock with your master password to turn it on again."
                return@launch
            }
            ctx.vault.unlockWithKey(key)
            onUnlocked()
        } catch (e: BiometricCancelled) {
            formShown = true
            runCatching { focus.requestFocus() }
        } catch (e: Exception) {
            formShown = true
            error = e.message
        }
    }

    fun submit() {
        if (busy || password.isEmpty()) return
        busy = true
        error = null
        scope.launch {
            try {
                ctx.vault.unlock(password)
                onUnlocked()
            } catch (e: Exception) {
                error = e.message ?: "Couldn't unlock"
            } finally {
                busy = false
            }
        }
    }

    LaunchedEffect(Unit) { if (bio) biometric() else focus.requestFocus() }
    LaunchedEffect(formShown) { if (formShown && compact) runCatching { focus.requestFocus() } }

    if (!formShown) return
    val page: @Composable (@Composable () -> Unit) -> Unit = if (compact) { c ->
        Column(Modifier.fillMaxWidth().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) { c() }
    } else { c -> FormPage(c) }
    page {
        if (!compact) Logo()
        Text("storii is locked", style = if (compact) MaterialTheme.typography.titleLarge else MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold)
        Text("$username · $server", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        PasswordField(password, { password = it }, "Master password", Modifier.focusRequester(focus), ImeAction.Go, ::submit)
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Button(onClick = ::submit, enabled = !busy && password.isNotEmpty(), modifier = Modifier.fillMaxWidth()) {
            if (busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
            else Text("Unlock")
        }
        if (bio) OutlinedButton(onClick = { biometric() }, modifier = Modifier.fillMaxWidth()) {
            Icon(Icons.Default.Fingerprint, null)
            Spacer(Modifier.size(8.dp))
            Text("Use biometrics")
        }
        extra()
    }
}

/** The colored letter badge in front of list rows. */
@Composable
fun TypeBadge(type: String?, modifier: Modifier = Modifier) {
    val (label, color) = when (type) {
        Item.PASSWORD -> "••" to MaterialTheme.colorScheme.primary
        Item.TOTP -> "2F" to Color(0xFF2E8B57)
        Item.API_KEY -> "{ }" to Color(0xFFB8741A)
        Item.CARD -> "▭" to Color(0xFF3A6FB0)
        Item.PASSKEY -> "⚿" to Color(0xFF6A4FB0)
        Item.NOTE -> "¶" to MaterialTheme.colorScheme.tertiary
        "website" -> "◍" to MaterialTheme.colorScheme.primary
        "app" -> "▣" to MaterialTheme.colorScheme.primary
        else -> "◇" to MaterialTheme.colorScheme.secondary
    }
    Box(modifier.size(40.dp).clip(RoundedCornerShape(12.dp)).background(color.copy(alpha = 0.15f)), contentAlignment = Alignment.Center) {
        Text(label, color = color, fontWeight = FontWeight.Bold, fontSize = 14.sp, textAlign = TextAlign.Center)
    }
}

@Composable
fun SmallTextButton(text: String, onClick: () -> Unit) = TextButton(onClick = onClick) { Text(text) }
