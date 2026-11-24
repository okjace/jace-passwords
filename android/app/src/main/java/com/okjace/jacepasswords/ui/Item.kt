package com.okjace.jacepasswords.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.OpenInNew
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.okjace.jacepasswords.JpApp
import com.okjace.jacepasswords.Match
import com.okjace.jacepasswords.Totp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

@Composable
private fun FieldRow(label: String, value: String, secret: Boolean = false, mono: Boolean = false, copyAs: String = label, extra: (@Composable () -> Unit)? = null) {
    if (value.isEmpty()) return
    val ctx = LocalContext.current
    var shown by remember { mutableStateOf(!secret) }
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(if (shown) value else "•".repeat(12), fontFamily = if (mono || secret) FontFamily.Monospace else null)
        }
        extra?.invoke()
        if (secret) IconButton(onClick = { shown = !shown }) { Icon(if (shown) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, "Show") }
        IconButton(onClick = { copy(ctx, value, copyAs) }) { Icon(Icons.Filled.ContentCopy, "Copy") }
    }
}

/** The 2FA code, ticking every second. */
@Composable
private fun TotpRow(secret: String) {
    val ctx = LocalContext.current
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(secret) { while (true) { delay(1000); now = System.currentTimeMillis() } }
    val code = runCatching { Totp.code(secret, now) }.getOrNull() ?: return
    Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text("One-time password (2FA)", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(if (code.code.length == 6) code.code.take(3) + " " + code.code.drop(3) else code.code, fontFamily = FontFamily.Monospace, fontSize = 26.sp,
                fontWeight = FontWeight.SemiBold, color = MaterialTheme.colorScheme.primary)
        }
        Text("${code.remaining}s", color = MaterialTheme.colorScheme.onSurfaceVariant)
        IconButton(onClick = { copy(ctx, code.code, "2FA code") }) { Icon(Icons.Filled.ContentCopy, "Copy") }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ItemScreen(id: String, onBack: () -> Unit, onEdit: () -> Unit) {
    val app = JpApp.app
    val ctx = LocalContext.current
    val item = runCatching { app.vault.item(id) }.getOrNull()
    if (item == null) { LaunchedEffect(id) { onBack() }; return }
    val f = item.optJSONObject("fields") ?: JSONObject()
    var confirm by remember { mutableStateOf(false) }
    Scaffold(topBar = {
        TopAppBar(title = { Text(item.optString("title"), maxLines = 1) }, navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } },
            actions = { if (item.optString("type") == "login") TextButton(onClick = onEdit) { Text("Edit") } })
    }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(4.dp)) {
                Tile(item.optString("title"), item.optString("type"), 56)
                Spacer(Modifier.width(14.dp))
                Column { Text(item.optString("title"), style = MaterialTheme.typography.titleLarge); Text(subtitleOf(item), color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            Card {
                when (item.optString("type")) {
                    "login" -> {
                        FieldRow("Username", f.optString("username"))
                        FieldRow("Password", f.optString("password"), secret = true)
                        if (f.optString("totp").isNotEmpty()) TotpRow(f.optString("totp"))
                        f.optJSONObject("signInWith")?.let { FieldRow("Sign in with", it.optString("provider").replaceFirstChar { c -> c.uppercase() } + it.optString("account").let { a -> if (a.isEmpty()) "" else " · $a" }) }
                        val pks = f.optJSONArray("passkeys")
                        if (pks != null && pks.length() > 0) FieldRow("Passkeys", "${pks.length()} saved (used in browsers with the extension)")
                    }
                    "card" -> {
                        FieldRow("Cardholder", f.optString("cardholder"))
                        FieldRow("Card number", f.optString("number"), secret = true, mono = true)
                        FieldRow("Expires", listOf(f.optString("expMonth"), f.optString("expYear")).filter { it.isNotEmpty() }.joinToString("/"))
                        FieldRow("Security code", f.optString("cvv"), secret = true)
                        FieldRow("PIN", f.optString("pin"), secret = true)
                    }
                    "identity" -> listOf("fullName" to "Name", "email" to "Email", "phone" to "Phone", "address1" to "Address", "address2" to "Address line 2",
                        "city" to "City", "state" to "State", "zip" to "ZIP / postal code", "country" to "Country", "birthday" to "Birthday", "company" to "Company")
                        .forEach { (k, l) -> FieldRow(l, f.optString(k)) }
                    "alias" -> { FieldRow("Alias", f.optString("alias")); FieldRow("Forwards to", f.optString("forwardsTo")) }
                    "note" -> FieldRow("Note", f.optString("body"))
                }
            }
            val urls = f.optJSONArray("urls") ?: JSONArray()
            if (urls.length() > 0) Card {
                (0 until urls.length()).map { urls.optString(it) }.filter { it.isNotEmpty() && !it.startsWith("androidapp://") }.forEach { u ->
                    FieldRow("Website", u, extra = {
                        IconButton(onClick = { runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(if ("://" in u) u else "https://$u"))) } }) {
                            Icon(Icons.AutoMirrored.Filled.OpenInNew, "Open")
                        }
                    })
                }
            }
            if (item.optString("type") != "note" && f.optString("notes").isNotEmpty()) Card { FieldRow("Notes", f.optString("notes")) }
            OutlinedButton(onClick = { confirm = true }, modifier = Modifier.fillMaxWidth()) { Text("Move to Trash") }
        }
    }
    if (confirm) AlertDialog(onDismissRequest = { confirm = false }, title = { Text("Move to Trash?") },
        text = { Text("You can restore it from Trash in the Jace Passwords app on your computer or the web.") },
        confirmButton = { TextButton(onClick = { app.vault.trash(id); app.changed(); confirm = false; onBack() }) { Text("Move to Trash") } },
        dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancel") } })
}

/** New or edited login. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EditLoginScreen(id: String?, onDone: (String?) -> Unit) {
    val app = JpApp.app
    val item = id?.let { runCatching { app.vault.item(it) }.getOrNull() }
    val f = item?.optJSONObject("fields") ?: JSONObject()
    var title by remember { mutableStateOf(item?.optString("title") ?: "") }
    var username by remember { mutableStateOf(f.optString("username")) }
    var password by remember { mutableStateOf(f.optString("password")) }
    var website by remember { mutableStateOf(f.optJSONArray("urls")?.optString(0) ?: "") }
    var totp by remember { mutableStateOf(f.optString("totp")) }
    var notes by remember { mutableStateOf(f.optString("notes")) }
    var show by remember { mutableStateOf(false) }
    val totpError = if (totp.isBlank()) null else runCatching { Totp.parse(totp); null }.getOrElse { it.message }

    fun save() {
        val urls = JSONArray(); website.trim().takeIf { it.isNotEmpty() }?.let { urls.put(if ("://" in it) it else "https://$it") }
        val fields = JSONObject().put("username", username.trim()).put("password", password).put("urls", urls).put("totp", totp.trim()).put("notes", notes)
        val t = title.ifBlank { Match.site(Match.host(website)).ifEmpty { "Login" } }
        val newId = if (item == null) app.vault.addItem("login", t, fields).optString("id") else { app.vault.updateItem(id!!, t, fields); id }
        app.changed()
        app.scope.launch(Dispatchers.IO) { app.syncNow() }
        onDone(newId)
    }

    Scaffold(topBar = {
        TopAppBar(title = { Text(if (item == null) "New login" else "Edit login") }, navigationIcon = { IconButton(onClick = { onDone(id) }) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Cancel") } },
            actions = { TextButton(onClick = { save() }, enabled = totpError == null) { Text("Save") } })
    }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedTextField(title, { title = it }, label = { Text("Title") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(username, { username = it }, label = { Text("Username or email") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email))
            OutlinedTextField(password, { password = it }, label = { Text("Password") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                visualTransformation = if (show) VisualTransformation.None else PasswordVisualTransformation(),
                trailingIcon = { IconButton(onClick = { show = !show }) { Icon(if (show) Icons.Filled.VisibilityOff else Icons.Filled.Visibility, "Show") } })
            Button(onClick = { password = Match.password(); show = true }) { Text("🎲 Generate a strong password") }
            OutlinedTextField(website, { website = it }, label = { Text("Website") }, singleLine = true, placeholder = { Text("example.com") }, modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            OutlinedTextField(totp, { totp = it }, label = { Text("2FA setup key, otpauth:// or steam:// link") }, singleLine = true, modifier = Modifier.fillMaxWidth(),
                isError = totpError != null, supportingText = { totpError?.let { Text(it) } })
            val ctx = LocalContext.current
            TextButton(onClick = { runCatching { ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://jace-passwords.vercel.app/steam"))) } }) {
                Text("Steam Guard? How to add Steam's codes")
            }
            OutlinedTextField(notes, { notes = it }, label = { Text("Notes") }, modifier = Modifier.fillMaxWidth().height(120.dp))
        }
    }
}
