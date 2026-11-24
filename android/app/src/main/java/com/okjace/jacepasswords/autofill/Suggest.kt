package com.okjace.jacepasswords.autofill

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.service.autofill.SaveInfo
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.okjace.jacepasswords.JpApp
import com.okjace.jacepasswords.Match
import com.okjace.jacepasswords.R
import com.okjace.jacepasswords.Totp
import kotlinx.coroutines.launch
import org.json.JSONObject

/** Builds what Android shows above the keyboard: matching logins, "Search Jace Passwords", or "Unlock". */
@Suppress("DEPRECATION")
object Suggest {
    fun row(ctx: Context, title: String, subtitle: String): RemoteViews =
        RemoteViews(ctx.packageName, R.layout.autofill_item).apply {
            setTextViewText(R.id.title, title)
            setTextViewText(R.id.subtitle, subtitle)
        }

    /** Logins for this website or app, best first. */
    fun matches(f: Fields): List<JSONObject> {
        val v = JpApp.app.vault
        if (!v.unlocked) return emptyList()
        return v.items().map { it to maxOf(Match.web(it, f.webDomain), if (f.webDomain.isEmpty()) Match.app(it, f.pkg) else 0) }
            .filter { it.second > 0 }.sortedWith(compareByDescending<Pair<JSONObject, Int>> { it.second }
                .thenByDescending { it.first.optString("lastUsedAt") }).map { it.first }
    }

    /** One login as a suggestion: fills the username and password (or the 2FA code into a code box). */
    fun dataset(ctx: Context, f: Fields, item: JSONObject): Dataset? {
        val fields = item.optJSONObject("fields") ?: JSONObject()
        val user = fields.optString("username"); val pw = fields.optString("password"); val totp = fields.optString("totp")
        val b = Dataset.Builder(row(ctx, item.optString("title"), user.ifEmpty { "Login" }))
        var any = false
        if (f.otp != null && totp.isNotEmpty()) {
            val code = runCatching { Totp.code(totp).code }.getOrNull() ?: return null
            b.setValue(f.otp, AutofillValue.forText(code), row(ctx, "2FA · ${item.optString("title")}", code)); any = true
        }
        if (f.username != null && user.isNotEmpty()) { b.setValue(f.username, AutofillValue.forText(user)); any = true }
        if (f.password != null && pw.isNotEmpty()) { b.setValue(f.password, AutofillValue.forText(pw)); any = true }
        return if (any) b.build() else null
    }

    private fun intentTo(ctx: Context, req: Request, code: Int): android.content.IntentSender {
        val i = Intent(ctx, AutofillActivity::class.java).putExtra(AutofillActivity.EXTRA_REQUEST, req)
        return PendingIntent.getActivity(ctx, code, i, PendingIntent.FLAG_CANCEL_CURRENT or PendingIntent.FLAG_MUTABLE).intentSender
    }

    fun where(f: Fields) = f.webDomain.ifEmpty { f.pkg.substringAfterLast('.') }

    /** The response for an unlocked vault: matching logins, then "Search Jace Passwords". */
    fun response(ctx: Context, f: Fields): FillResponse {
        val r = FillResponse.Builder()
        matches(f).take(5).forEach { dataset(ctx, f, it)?.let(r::addDataset) }
        val search = Dataset.Builder(row(ctx, "Search Jace Passwords", "Pick any login for ${where(f)}"))
        f.ids.forEach { search.setValue(it, null) }
        search.setAuthentication(intentTo(ctx, Request.of("pick", f), 2))
        r.addDataset(search.build())
        saveInfo(f)?.let(r::setSaveInfo)
        return r.build()
    }

    /** Locked: one "Unlock Jace Passwords" suggestion that opens the unlock screen, then shows the logins. */
    fun locked(ctx: Context, f: Fields): FillResponse {
        val r = FillResponse.Builder()
        r.setAuthentication(f.ids, intentTo(ctx, Request.of("unlock", f), 1), row(ctx, "Unlock Jace Passwords", "To fill your login for ${where(f)}"))
        saveInfo(f)?.let(r::setSaveInfo)
        return r.build()
    }

    fun saveInfo(f: Fields): SaveInfo? {
        if (f.password == null) return null
        val ids = listOfNotNull(f.username, f.password).toTypedArray()
        val type = SaveInfo.SAVE_DATA_TYPE_PASSWORD or (if (f.username != null) SaveInfo.SAVE_DATA_TYPE_USERNAME else 0)
        return SaveInfo.Builder(type, ids).build()
    }

    /** Saves (or updates) the login just typed into an app or site. */
    fun save(f: Fields) {
        val v = JpApp.app.vault
        val pw = f.passwordValue?.takeIf { it.isNotEmpty() } ?: return
        val user = f.usernameValue ?: ""
        val existing = matches(f).firstOrNull { it.optJSONObject("fields")?.optString("username").orEmpty() == user }
        if (existing != null) {
            if (existing.optJSONObject("fields")?.optString("password") != pw) {
                v.updateItem(existing.optString("id"), null, JSONObject().put("password", pw))
            }
        } else {
            val url = if (f.webDomain.isNotEmpty()) "https://${f.webDomain}" else "androidapp://${f.pkg}"
            val title = if (f.webDomain.isNotEmpty()) Match.site(Match.host(f.webDomain)) else f.pkg.substringAfterLast('.').replaceFirstChar { it.uppercase() }
            v.addItem("login", title, JSONObject().put("username", user).put("password", pw).put("urls", org.json.JSONArray().put(url)))
        }
        JpApp.app.changed()
        JpApp.app.scope.launch { JpApp.app.syncNow() }
    }
}
