package com.okjace.jacepasswords.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.okjace.jacepasswords.JpApp
import com.okjace.jacepasswords.Vault
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The Jace Passwords logo tile with a title, used at the top of the first screens. */
@Composable
fun Logo(title: String, subtitle: String? = null) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Surface(color = JaceGreen, shape = RoundedCornerShape(18.dp), modifier = Modifier.size(64.dp)) {
            Icon(Icons.Filled.Lock, null, tint = androidx.compose.ui.graphics.Color(0xFF0C1410), modifier = Modifier.padding(16.dp))
        }
        Spacer(Modifier.height(14.dp))
        Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        if (subtitle != null) Text(subtitle, color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 6.dp))
    }
}

/**
 * Unlock (or, with restore = true, open the vault from your Jace account here for the first time). Asks only for
 * what this vault needs: a master password (and Secret Key if it uses one), or nothing for a Jace-account vault.
 */
@Composable
fun UnlockScreen(restore: Boolean = false, keyMode: String, needsSecretKey: Boolean, onDone: () -> Unit) {
    val app = JpApp.app
    val scope = rememberCoroutineScope()
    var password by remember { mutableStateOf("") }
    var secretKey by remember { mutableStateOf("") }
    var rememberHere by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val needsPassword = keyMode == "password"

    fun go() {
        busy = true; error = null
        scope.launch {
            try {
                withContext(Dispatchers.Default) { // scrypt takes a few seconds on purpose
                    if (restore) app.restore(password.ifEmpty { null }, secretKey.ifEmpty { null })
                    else app.unlock(password.ifEmpty { null }, secretKey.ifEmpty { null })
                    if (rememberHere && needsPassword) app.vault.remember(true)
                }
                onDone()
            } catch (e: Exception) {
                error = e.message ?: "Couldn't unlock."
            } finally { busy = false }
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.Center) {
        Spacer(Modifier.height(40.dp))
        val who = app.account()
        Logo(if (restore) "Open your vault" else "Unlock Jace Passwords",
            when {
                restore && who != null -> "Your vault is on your Jace account @${who.optString("username")}."
                keyMode == "jace" -> "This vault unlocks with your Jace account."
                keyMode == "device" -> "This vault opens on this phone without a password."
                else -> null
            })
        Spacer(Modifier.height(24.dp))
        if (needsPassword) {
            OutlinedTextField(password, { password = it }, label = { Text("Master password") }, singleLine = true,
                visualTransformation = PasswordVisualTransformation(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth())
            if (needsSecretKey) {
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(secretKey, { secretKey = it }, label = { Text("Secret Key (J1-…)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(rememberHere, { rememberHere = it })
                Text("Remember my password on this phone", style = MaterialTheme.typography.bodyMedium)
            }
        }
        if (error != null) Text(error!!, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(vertical = 8.dp))
        Spacer(Modifier.height(8.dp))
        Button(onClick = { go() }, enabled = !busy && (!needsPassword || password.isNotEmpty()), modifier = Modifier.fillMaxWidth().height(52.dp)) {
            Text(when { busy -> "Unlocking…"; keyMode == "jace" -> "Unlock with Jace"; keyMode == "device" -> "Open"; else -> "Unlock" })
        }
    }
}

/** What the unlock screen needs to know about this vault (or the one on Jace, when restoring). */
data class VaultInfo(val keyMode: String, val needsSecretKey: Boolean)

fun localInfo(): VaultInfo {
    val f = JpApp.app.vault.file()
    return VaultInfo(Vault.keyMode(f), Vault.usesSecretKey(f) && JpApp.app.store.device().optString("secretKey").isEmpty())
}
