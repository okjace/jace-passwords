package com.okjace.jacepasswords.autofill

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import android.view.autofill.AutofillManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.okjace.jacepasswords.JpApp
import com.okjace.jacepasswords.ui.JaceTheme
import com.okjace.jacepasswords.ui.Tile
import com.okjace.jacepasswords.ui.UnlockScreen
import com.okjace.jacepasswords.ui.localInfo
import com.okjace.jacepasswords.ui.subtitleOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Opened from an autofill suggestion: unlock, pick any login, or unlock-then-save. Answers Android and closes. */
class AutofillActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        @Suppress("DEPRECATION")
        val req: Request = (if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(EXTRA_REQUEST, Request::class.java) else intent.getParcelableExtra(EXTRA_REQUEST))
            ?: return finish()
        val f = req.fields()
        val app = JpApp.app
        setContent {
            JaceTheme {
                Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    var unlocked by remember { mutableStateOf(app.vault.unlocked) }
                    LaunchedEffect(Unit) {
                        if (!unlocked && (app.vault.remembered() || app.vault.keyMode() == "device" || (app.vault.keyMode() == "jace" && app.signedIn()))) {
                            withContext(Dispatchers.IO) { runCatching { app.unlock(null, null) } }
                            unlocked = app.vault.unlocked
                        }
                    }
                    if (!unlocked) {
                        val info = localInfo()
                        UnlockScreen(keyMode = info.keyMode, needsSecretKey = info.needsSecretKey) { unlocked = true }
                    } else when (req.mode) {
                        "unlock" -> LaunchedEffect(Unit) { answer(Suggest.response(this@AutofillActivity, f)) }
                        "save" -> LaunchedEffect(Unit) { runCatching { Suggest.save(f) }; setResult(Activity.RESULT_OK); finish() }
                        else -> Picker(f)
                    }
                }
            }
        }
    }

    private fun answer(result: android.os.Parcelable) {
        setResult(Activity.RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, result))
        finish()
    }

    @androidx.compose.runtime.Composable
    private fun Picker(f: Fields) {
        var q by remember { mutableStateOf("") }
        val all = JpApp.app.vault.items().filter { it.optString("type") == "login" }
            .filter { q.isBlank() || (it.optString("title") + " " + subtitleOf(it)).contains(q.trim(), true) }
            .sortedBy { it.optString("title").lowercase() }
        Column(Modifier.fillMaxSize().padding(16.dp)) {
            Text("Fill a login into ${Suggest.where(f)}", style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(bottom = 12.dp))
            OutlinedTextField(q, { q = it }, placeholder = { Text("Search logins") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            LazyColumn {
                items(all, key = { it.optString("id") }) { item ->
                    Row(Modifier.fillMaxWidth().clickable {
                        val ds = Suggest.dataset(this@AutofillActivity, f, item)
                        if (ds != null) { JpApp.app.vault.markUsed(item.optString("id")); answer(ds) }
                    }.padding(vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                        Tile(item.optString("title"), "login")
                        Spacer(Modifier.width(12.dp))
                        Column { Text(item.optString("title"), fontWeight = FontWeight.SemiBold); Text(subtitleOf(item), color = MaterialTheme.colorScheme.onSurfaceVariant) }
                    }
                }
            }
        }
    }

    companion object { const val EXTRA_REQUEST = "request" }
}
