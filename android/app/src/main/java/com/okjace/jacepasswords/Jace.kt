package com.okjace.jacepasswords

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

/**
 * The Jace Passwords site (jace-passwords.vercel.app/api/jace/...), with this phone's Jace sign-in token, exactly like
 * the browser extension: your account, sync of the (encrypted) vault, and the key for vaults that unlock with Jace.
 */
class Jace(private val token: () -> String?) {
    data class Reply(val status: Int, val body: JSONObject)
    class SignedOut : Exception("Sign in with Jace again.")

    fun call(method: String, path: String, body: JSONObject? = null, headers: Map<String, String> = emptyMap()): Reply {
        val t = token() ?: throw SignedOut()
        val c = URL("$WEB/api/jace/$path").openConnection() as HttpURLConnection
        c.requestMethod = method
        c.connectTimeout = 20000; c.readTimeout = 30000
        c.setRequestProperty("Authorization", "Bearer $t")
        c.setRequestProperty("X-Jace-Passwords", "1")
        c.setRequestProperty("Accept", "application/json")
        c.setRequestProperty("User-Agent", "JacePasswords-Android/${BuildConfigInfo.version}")
        headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
        if (body != null) {
            c.doOutput = true
            c.setRequestProperty("Content-Type", "application/json")
            c.outputStream.use { it.write(body.toString().toByteArray()) }
        }
        val status = c.responseCode
        val text = (if (status < 400) c.inputStream else c.errorStream)?.bufferedReader()?.use { it.readText() } ?: ""
        return Reply(status, runCatching { JSONObject(text) }.getOrElse { JSONObject() })
    }

    /** {"id","username","name","picture"} or null if the sign-in no longer works. */
    fun me(): JSONObject? {
        val r = call("GET", "me")
        if (r.status == 401) throw SignedOut()
        return if (r.status == 200) r.body.optJSONObject("user") else null
    }

    fun vaultKey(userId: String): ByteArray {
        val r = call("GET", "vault-key")
        if (r.status != 200) throw Vault.VaultError(r.body.optString("error_description").ifEmpty { "Couldn't get your vault key. Sign in with Jace again." })
        if (r.body.optString("sub") != userId) throw Vault.VaultError("That key is for a different Jace account.")
        return Base64.getDecoder().decode(r.body.getString("key"))
    }

    /** (vault file, version), or (null, 0) if nothing is synced yet. */
    fun pull(): Pair<JSONObject?, Int> {
        val r = call("GET", "sync")
        if (r.status == 404) return null to 0
        if (r.status == 401) throw SignedOut()
        if (r.status != 200) throw Vault.VaultError(r.body.optString("error_description").ifEmpty { "Jace sync failed (${r.status})." })
        val file = JSONObject(String(Base64.getDecoder().decode(r.body.getString("payload"))))
        return file to r.body.optInt("version")
    }

    /** The new version, or -1 if someone else synced first (pull and try again). */
    fun push(file: JSONObject, version: Int): Int {
        val payload = Base64.getEncoder().encodeToString(file.toString().toByteArray())
        val r = call("PUT", "sync", JSONObject().put("payload", payload).put("device", "Jace Passwords Android"), mapOf("If-Match" to "\"$version\""))
        if (r.status == 412) return -1
        if (r.status == 401) throw SignedOut()
        if (r.status != 200) throw Vault.VaultError(r.body.optString("error_description").ifEmpty { "Jace sync failed (${r.status})." })
        return r.body.optInt("version")
    }

    companion object {
        const val WEB = "https://jace-passwords.vercel.app"
        const val ANDROID_RETURN = "$WEB/android-auth"
        fun signInUrl(appState: String) = "$WEB/api/jace/signin?ext_redirect=" + java.net.URLEncoder.encode(ANDROID_RETURN, "UTF-8") + "&app_state=$appState"
    }
}

/** Filled in by JpApp from the installed package, so code without a Context can read the version. */
object BuildConfigInfo { var version = "0" }
