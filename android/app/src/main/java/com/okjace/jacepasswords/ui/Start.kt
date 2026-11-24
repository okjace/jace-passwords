package com.okjace.jacepasswords.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.okjace.jacepasswords.JpApp
import com.okjace.jacepasswords.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * No vault on this phone yet. Signed out: sign in with Jace, or use it on this phone only. Signed in: open the
 * vault from your Jace account, or make one.
 */
@Composable
fun StartScreen(onSignIn: () -> Unit, onReady: () -> Unit) {
    val app = JpApp.app
    val scope = rememberCoroutineScope()
    var remote by remember { mutableStateOf<JSONObject?>(null) }
    var checked by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var creating by remember { mutableStateOf(false) }
    val signedIn = app.signedIn()

    LaunchedEffect(signedIn) {
        if (signedIn) {
            remote = withContext(Dispatchers.IO) { runCatching { app.fetchRemote() }.onFailure { error = it.message }.getOrNull() }
        }
        checked = true
    }

    if (signedIn && remote != null) {
        UnlockScreen(restore = true, keyMode = Vault.keyMode(remote), needsSecretKey = Vault.usesSecretKey(remote), onDone = onReady)
        return
    }
    if (creating) { CreateScreen(onDone = onReady, onBack = { creating = false }); return }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Spacer(Modifier.height(48.dp))
        Logo("Every password, card and code. One vault.",
            "Logins with passkeys and 2FA codes, cards, notes and addresses: end-to-end encrypted and filled in for you.")
        Spacer(Modifier.height(16.dp))
        if (error != null) Text(error!!, color = MaterialTheme.colorScheme.error)
        when {
            !signedIn -> {
                Button(onClick = onSignIn, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Sign in with Jace") }
                Text("Sync your encrypted vault with your computer and browsers.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                OutlinedButton(onClick = { creating = true }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Use on this phone only") }
            }
            !checked -> Text("Looking for your vault on Jace…")
            else -> {
                Text("There's no vault on your Jace account yet.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                Button(onClick = { creating = true }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Create your vault") }
                TextButton(onClick = { app.signOut() }) { Text("Use a different Jace account") }
            }
        }
    }
}

@Composable
fun CreateScreen(onDone: () -> Unit, onBack: () -> Unit) {
    val app = JpApp.app
    val scope = rememberCoroutineScope()
    var pw by remember { mutableStateOf("") }
    var pw2 by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var secretKey by remember { mutableStateOf<String?>(null) }
    val signedIn = app.signedIn()

    fun make(password: String?) {
        busy = true; error = null
        scope.launch {
            try {
                val sk = withContext(Dispatchers.Default) { app.create(password) }
                if (sk != null) secretKey = sk else onDone()
            } catch (e: Exception) { error = e.message } finally { busy = false }
        }
    }

    if (secretKey != null) {
        Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Spacer(Modifier.height(48.dp))
            Logo("Save your Secret Key", "You need it with your master password to open this vault on another device. Write it down or keep it somewhere safe.")
            Card { Text(secretKey!!, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(16.dp)) }
            Button(onClick = onDone, modifier = Modifier.fillMaxWidth()) { Text("I saved it") }
        }
        return
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Spacer(Modifier.height(40.dp))
        Logo("Create your vault")
        Text("A master password makes it end-to-end encrypted: only you can open it, and nobody can reset it for you.", color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedTextField(pw, { pw = it }, label = { Text("Master password") }, singleLine = true, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
        OutlinedTextField(pw2, { pw2 = it }, label = { Text("Confirm master password") }, singleLine = true, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
        if (error != null) Text(error!!, color = MaterialTheme.colorScheme.error)
        Button(onClick = { if (pw != pw2) error = "Those passwords don't match." else make(pw) }, enabled = !busy && pw.isNotEmpty(),
            modifier = Modifier.fillMaxWidth().height(52.dp)) { Text(if (busy) "Encrypting…" else "Create vault") }
        OutlinedButton(onClick = { make(null) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (signedIn) "Skip: unlock with my Jace account" else "Skip: no master password")
        }
        Text(if (signedIn) "Without a master password your vault is still encrypted, but the Jace Passwords server holds its key for your account." else
            "Without a master password your vault is still encrypted, but anyone who can use this phone can open it.",
            color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall)
        TextButton(onClick = onBack) { Text("Back") }
    }
}
