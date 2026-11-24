package com.okjace.jacepasswords

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import com.okjace.jacepasswords.ui.EditLoginScreen
import com.okjace.jacepasswords.ui.HomeScreen
import com.okjace.jacepasswords.ui.ItemScreen
import com.okjace.jacepasswords.ui.JaceTheme
import com.okjace.jacepasswords.ui.SettingsScreen
import com.okjace.jacepasswords.ui.StartScreen
import com.okjace.jacepasswords.ui.UnlockScreen
import com.okjace.jacepasswords.ui.localInfo
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : ComponentActivity() {
    private val app get() = JpApp.app

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE) // no screenshots of the vault
        enableEdgeToEdge()
        if (Build.VERSION.SDK_INT >= 33) requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        handle(intent)
        setContent {
            JaceTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    val tick by app.changes.collectAsState()
                    var screen by remember { mutableStateOf("home") }
                    var itemId by remember { mutableStateOf<String?>(null) }
                    LaunchedEffect(Unit) { // vaults that open without typing anything
                        if (app.vault.exists() && !app.vault.unlocked && (app.vault.remembered() || app.vault.keyMode() == "device" ||
                                (app.vault.keyMode() == "jace" && app.signedIn()))) {
                            withContext(Dispatchers.IO) { runCatching { app.unlock(null, null) } }
                        }
                        if (app.vault.unlocked) withContext(Dispatchers.IO) { app.syncNow() }
                    }
                    key(tick) {
                        when {
                            !app.vault.exists() -> StartScreen(onSignIn = ::signIn, onReady = { screen = "home"; app.changed() })
                            !app.vault.unlocked -> localInfo().let { UnlockScreen(keyMode = it.keyMode, needsSecretKey = it.needsSecretKey, onDone = { app.changed() }) }
                            screen == "item" && itemId != null -> {
                                BackHandler { screen = "home" }
                                ItemScreen(itemId!!, onBack = { screen = "home" }, onEdit = { screen = "edit" })
                            }
                            screen == "edit" || screen == "new" -> {
                                BackHandler { screen = if (screen == "edit") "item" else "home" }
                                EditLoginScreen(if (screen == "edit") itemId else null) { id -> itemId = id; screen = if (id != null) "item" else "home" }
                            }
                            screen == "settings" -> { BackHandler { screen = "home" }; SettingsScreen(onBack = { screen = "home" }, onSignIn = ::signIn) }
                            else -> HomeScreen(onOpen = { itemId = it; screen = "item" }, onAdd = { screen = "new" }, onSettings = { screen = "settings" })
                        }
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) { super.onNewIntent(intent); handle(intent) }
    override fun onResume() { super.onResume(); app.checkAutoLock() }

    private fun signIn() {
        val url = Jace.signInUrl(app.newSignInState())
        runCatching { CustomTabsIntent.Builder().build().launchUrl(this, Uri.parse(url)) }
            .onFailure { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
    }

    /** The sign-in coming back from Jace (verified App Link, or jacepasswords://auth from the fallback page). */
    private fun handle(intent: Intent?) {
        if (intent?.action == ACTION_INSTALL_UPDATE) { lifecycleScope.launch { withContext(Dispatchers.IO) { Updates.check(this@MainActivity, true) }; Updates.install(this@MainActivity) }; return }
        val data = intent?.data ?: return
        val params = (data.encodedFragment ?: data.encodedQuery ?: "").split("&").filter { "=" in it }
            .associate { Uri.decode(it.substringBefore("=")) to Uri.decode(it.substringAfter("=")) }
        val token = params["token"]
        if (token.isNullOrEmpty()) {
            params["error"]?.let { Toast.makeText(this, "Sign-in didn't work: $it", Toast.LENGTH_LONG).show() }
            return
        }
        lifecycleScope.launch {
            try {
                val user = withContext(Dispatchers.IO) { app.finishSignIn(token, params["expires_in"]?.toLongOrNull() ?: 86400, params["app_state"] ?: "") }
                Toast.makeText(this@MainActivity, "Signed in as @${user.optString("username")}", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, e.message ?: "Sign-in didn't work.", Toast.LENGTH_LONG).show()
            }
        }
    }

    companion object { const val ACTION_INSTALL_UPDATE = "com.okjace.jacepasswords.INSTALL_UPDATE" }
}
