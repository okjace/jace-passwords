package com.okjace.jacepasswords.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.okjace.jacepasswords.JpApp
import org.json.JSONObject

private val FILTERS = listOf("all" to "All", "login" to "Logins", "card" to "Cards", "note" to "Notes", "identity" to "Identities", "2fa" to "2FA codes")

fun subtitleOf(i: JSONObject): String {
    val f = i.optJSONObject("fields") ?: JSONObject()
    return when (i.optString("type")) {
        "login" -> f.optJSONObject("signInWith")?.let { "Sign in with ${it.optString("provider").replaceFirstChar { c -> c.uppercase() }}" }
            ?: f.optString("username").ifEmpty { f.optJSONArray("urls")?.optString(0) ?: "" }
        "card" -> "${f.optString("brand").ifEmpty { "Card" }} •••• ${f.optString("number").takeLast(4)}"
        "note" -> f.optString("body").lineSequence().firstOrNull()?.take(60) ?: ""
        "identity" -> f.optString("fullName").ifEmpty { f.optString("email") }
        "alias" -> f.optString("alias")
        else -> ""
    }
}

@Composable
fun Tile(title: String, type: String, size: Int = 40) {
    val icon = when (type) { "card" -> "💳"; "note" -> "📝"; "identity" -> "🪪"; "alias" -> "📧"; else -> null }
    var h = 0; title.forEach { h = h * 31 + it.code }
    val bg = Color.hsl(((h % 360) + 360) % 360f, 0.55f, 0.48f)
    Box(Modifier.size(size.dp).clip(RoundedCornerShape(10.dp)).background(if (icon != null) Color(0xFF3B46C4) else bg), contentAlignment = Alignment.Center) {
        Text(icon ?: (title.trim().firstOrNull()?.uppercase() ?: "?"), color = Color.White, fontWeight = FontWeight.Bold, fontSize = (size / 2.4).sp)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(onOpen: (String) -> Unit, onAdd: () -> Unit, onSettings: () -> Unit) {
    val app = JpApp.app
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("all") }
    val items = runCatching { app.vault.items() }.getOrDefault(emptyList())
        .filter { i ->
            when (filter) { "all" -> true; "2fa" -> i.optJSONObject("fields")?.optString("totp").orEmpty().isNotEmpty(); else -> i.optString("type") == filter }
        }
        .filter { i -> query.isBlank() || (i.optString("title") + " " + subtitleOf(i) + " " + i.optJSONObject("fields")?.optJSONArray("urls")).contains(query.trim(), true) }
        .sortedWith(compareByDescending<JSONObject> { it.optBoolean("favorite") }.thenBy { it.optString("title").lowercase() })

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Jace Passwords") }, actions = {
                IconButton(onClick = { app.lock() }) { Icon(Icons.Filled.Lock, "Lock") }
                IconButton(onClick = onSettings) { Icon(Icons.Filled.Settings, "Settings") }
            })
        },
        floatingActionButton = { FloatingActionButton(onClick = onAdd, containerColor = MaterialTheme.colorScheme.primary) { Icon(Icons.Filled.Add, "New login") } },
    ) { pad ->
        Column(Modifier.padding(pad).fillMaxSize()) {
            OutlinedTextField(query, { query = it }, placeholder = { Text("Search your vault") }, leadingIcon = { Icon(Icons.Filled.Search, null) },
                singleLine = true, modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp))
            Row(Modifier.horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FILTERS.forEach { (k, label) -> FilterChip(selected = filter == k, onClick = { filter = k }, label = { Text(label) }) }
            }
            if (items.isEmpty()) {
                Text(if (query.isBlank()) "Nothing here yet. Tap + to add a login." else "No matches.", color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(24.dp))
            }
            LazyColumn(Modifier.fillMaxSize()) {
                items(items, key = { it.optString("id") }) { i ->
                    Row(Modifier.fillMaxWidth().clickable { onOpen(i.optString("id")) }.padding(horizontal = 16.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        Tile(i.optString("title"), i.optString("type"))
                        Spacer(Modifier.width(14.dp))
                        Column(Modifier.weight(1f)) {
                            Text((if (i.optBoolean("favorite")) "⭐ " else "") + i.optString("title"), fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                            Text(subtitleOf(i), color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        }
                    }
                }
                item { Spacer(Modifier.height(88.dp)) }
            }
        }
    }
}
