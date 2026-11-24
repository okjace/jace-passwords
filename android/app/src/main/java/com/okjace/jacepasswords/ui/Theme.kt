package com.okjace.jacepasswords.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import android.widget.Toast
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import android.os.Handler
import android.os.Looper

/** Jace colors: green accent, dark charcoal (follows the phone's light/dark setting). */
val JaceGreen = Color(0xFF3DDC84)
private val dark = darkColorScheme(
    primary = JaceGreen, onPrimary = Color(0xFF0C1410), background = Color(0xFF111317), onBackground = Color(0xFFE6E8EB),
    surface = Color(0xFF1C1F26), onSurface = Color(0xFFE6E8EB), surfaceVariant = Color(0xFF23272F), onSurfaceVariant = Color(0xFF8B919C),
    secondaryContainer = Color(0xFF1F3A2B), onSecondaryContainer = JaceGreen, error = Color(0xFFFF6B6B),
)
private val light = lightColorScheme(
    primary = Color(0xFF1F9D5A), onPrimary = Color.White, background = Color(0xFFF4F5F7), onBackground = Color(0xFF16181D),
    surface = Color.White, onSurface = Color(0xFF16181D), surfaceVariant = Color(0xFFECEEF1), onSurfaceVariant = Color(0xFF5D6470),
    secondaryContainer = Color(0xFFD6F2E2), onSecondaryContainer = Color(0xFF1F9D5A), error = Color(0xFFE0464F),
)

@Composable
fun JaceTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) dark else light, content = content)
}

/** Copies, marked sensitive (hidden from the clipboard preview), and clears it after 30 seconds. */
fun copy(ctx: Context, text: String, what: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText(what, text)
    if (Build.VERSION.SDK_INT >= 33) clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
    cm.setPrimaryClip(clip)
    if (Build.VERSION.SDK_INT < 33) Toast.makeText(ctx, "$what copied", Toast.LENGTH_SHORT).show()
    Handler(Looper.getMainLooper()).postDelayed({
        runCatching { if (cm.primaryClip?.getItemAt(0)?.text?.toString() == text) cm.clearPrimaryClip() }
    }, 30_000)
}
