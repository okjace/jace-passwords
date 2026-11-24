package com.okjace.jacepasswords.ui

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.autofill.AutofillManager
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.okjace.jacepasswords.JpApp
import com.okjace.jacepasswords.Updates
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
private fun Section(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(title, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.titleMedium)
            content()
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(onBack: () -> Unit, onSignIn: () -> Unit) {
    val app = JpApp.app
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val sync by app.syncStatus.collectAsState()
    val update by Updates.state.collectAsState()
    val afm = ctx.getSystemService(AutofillManager::class.java)
    val autofillOn = afm?.hasEnabledAutofillServices() == true
    var remembered by remember { mutableStateOf(app.vault.remembered()) }
    var auto by remember { mutableStateOf(Updates.autoUpdate(ctx)) }
    val acct = app.account()

    Scaffold(topBar = {
        TopAppBar(title = { Text("Settings") }, navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back") } })
    }) { pad ->
        Column(Modifier.padding(pad).fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Section("Autofill") {
                Text(if (autofillOn) "✓ Jace Passwords fills sign-ins in your apps and browsers." else
                    "Turn on Jace Passwords as your autofill service to fill sign-ins in every app and browser.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                if (!autofillOn) Button(onClick = {
                    runCatching { ctx.startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE).setData(Uri.parse("package:${ctx.packageName}"))) }
                }) { Text("Turn on autofill") }
            }
            Section("Jace account") {
                if (acct != null) {
                    Text("@${acct.optString("username")} · ${sync.ifEmpty { "Synced with Jace" }}", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { scope.launch(Dispatchers.IO) { app.syncNow() } }) { Text("Sync now") }
                        OutlinedButton(onClick = { app.signOut() }) { Text("Sign out") }
                    }
                } else {
                    Text("Sign in to sync your vault with your computer, browsers and other phones.", color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Button(onClick = onSignIn) { Text("Sign in with Jace") }
                }
            }
            if (app.vault.keyMode() == "password") Section("Unlocking") {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Remember my master password on this phone")
                        Text("Opens and fills without typing it. Anyone who can use this phone can open your vault.",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(remembered, { on -> runCatching { app.vault.remember(on) }; remembered = app.vault.remembered() })
                }
            }
            Section("Updates") {
                Text("Version ${com.okjace.jacepasswords.BuildConfigInfo.version}. ${update.message}", color = MaterialTheme.colorScheme.onSurfaceVariant)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (update.ready) Button(onClick = { Updates.install(ctx) }) { Text("Install ${update.version}") }
                    else OutlinedButton(onClick = { scope.launch { withContext(Dispatchers.IO) { Updates.check(ctx, download = true) } } }) { Text("Check for updates") }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Column(Modifier.weight(1f)) {
                        Text("Update automatically")
                        Text("Downloads new versions and installs them by itself (Android may ask once to allow it).",
                            style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    Switch(auto, { auto = it; Updates.setAutoUpdate(ctx, it) })
                }
            }
            OutlinedButton(onClick = { app.lock() }, modifier = Modifier.fillMaxWidth()) { Text("Lock now") }
        }
    }
}
