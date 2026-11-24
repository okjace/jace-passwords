package com.okjace.jacepasswords

import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant
import java.util.UUID

/** Where the vault and this device's settings are kept (Store on the phone; memory in tests). */
interface VaultIO {
    fun load(): JSONObject?
    fun save(file: JSONObject?)
    fun device(): JSONObject
    fun updateDevice(change: (JSONObject) -> Unit): JSONObject
}

/**
 * One vault, the same as vault.py / webvault.js: the file is {format, account, kdf, salt, wrappedKey, keyChangedAt,
 * data: AES-GCM(vault key, JSON), updatedAt}. The data JSON is kept as-is (unknown fields survive a save), so the
 * phone never drops anything another Jace Passwords app added.
 */
class Vault(private val io: VaultIO) {
    class VaultError(message: String) : Exception(message)

    var key: ByteArray? = null; private set
    var data: JSONObject? = null; private set
    private var meta = JSONObject()
    var lastActivity = System.currentTimeMillis()

    val unlocked get() = data != null
    fun exists() = io.load() != null
    fun file(): JSONObject? = io.load()
    fun touch() { lastActivity = System.currentTimeMillis() }

    fun require(): JSONObject { touch(); return data ?: throw VaultError("The vault is locked.") }

    companion object {
        const val FORMAT = "jace-passwords/1"
        fun now(): String = Instant.now().toString()
        fun newId(): String = UUID.randomUUID().toString().replace("-", "")
        fun keyMode(f: JSONObject?): String = when (f?.optJSONObject("kdf")?.optString("name")) { "jace" -> "jace"; "device" -> "device"; else -> "password" }
        fun usesSecretKey(f: JSONObject?): Boolean {
            val k = f?.optJSONObject("kdf") ?: return false
            return k.optString("name") == "scrypt" && !(k.has("secretKey") && !k.optBoolean("secretKey", true))
        }
        fun emptyData(): JSONObject {
            val t = now()
            return JSONObject()
                .put("vaults", JSONArray().put(JSONObject().put("id", newId()).put("name", "Personal").put("icon", "🔐").put("color", "#3ddc84")
                    .put("travelSafe", true).put("createdAt", t).put("updatedAt", t)))
                .put("items", JSONArray())
                .put("settings", JSONObject().put("autoLockMinutes", 10).put("clipboardClearSeconds", 30))
                .put("generatorHistory", JSONArray())
                .put("createdAt", t)
        }
    }

    fun keyMode() = keyMode(io.load())
    private fun deviceKey(create: Boolean = false): ByteArray? {
        io.device().optString("deviceKey").takeIf { it.isNotEmpty() }?.let { return Crypto.b64d(it) }
        if (!create) return null
        val k = Crypto.rand(32)
        io.updateDevice { it.put("deviceKey", Crypto.b64e(k)) }
        return k
    }

    // ---------- opening ----------
    /** Opens the vault on this phone, or [remote] (a synced copy being restored, then saved here). */
    fun unlock(password: String?, secretKey: String?, jaceKey: ByteArray?, remote: JSONObject? = null) {
        val f = remote ?: io.load() ?: throw VaultError("There's no vault on this phone yet.")
        if (f.optString("format") != FORMAT) throw VaultError("This isn't a Jace Passwords vault.")
        if (remote == null && keyMode(f) == "password" && password.isNullOrEmpty()) {
            if (io.device().has("rememberedKey")) return unlockRemembered(f)
            throw VaultError("Enter your master password.")
        }
        val sk = if (usesSecretKey(f)) (secretKey?.takeIf { it.isNotBlank() } ?: io.device().optString("secretKey").takeIf { it.isNotEmpty() }
            ?: throw VaultError("Enter your Secret Key (it's on your Emergency Kit).")) else null
        val kek = Crypto.deriveKek(password, sk, Crypto.b64d(f.getString("salt")), f.getJSONObject("kdf"), jaceKey, deviceKey())
        val k = Crypto.open(kek, f.getJSONObject("wrappedKey"), Crypto.AAD_KEY)
        val d = JSONObject(String(Crypto.open(k, f.getJSONObject("data"), Crypto.AAD_DATA)))
        key = k; data = d; meta = metaOf(f)
        if (sk != null && !secretKey.isNullOrBlank()) io.updateDevice { it.put("secretKey", secretKey.trim()) }
        if (remote != null) save()
        touch()
    }

    private fun metaOf(f: JSONObject) = JSONObject(f.toString()).apply { remove("data"); remove("updatedAt") }

    private fun unlockRemembered(f: JSONObject) {
        try {
            val k = Crypto.open(deviceKey() ?: throw VaultError(""), io.device().getJSONObject("rememberedKey"), Crypto.AAD_REMEMBER)
            data = JSONObject(String(Crypto.open(k, f.getJSONObject("data"), Crypto.AAD_DATA)))
            key = k; meta = metaOf(f); touch()
        } catch (e: Exception) {
            io.updateDevice { it.remove("rememberedKey") }
            throw VaultError("Enter your master password.")
        }
    }

    fun lock() { key = null; data = null }

    fun remembered() = io.device().has("rememberedKey") && keyMode() == "password"

    /** Opens without the master password on this phone (the vault key, sealed with this phone's own key). */
    fun remember(on: Boolean) {
        val k = key ?: throw VaultError("The vault is locked.")
        io.updateDevice { d -> if (on) d.put("rememberedKey", Crypto.seal(deviceKey(true)!!, k, Crypto.AAD_REMEMBER)) else d.remove("rememberedKey") }
    }

    // ---------- making one ----------
    /**
     * A new vault. password == null: no master password (unlocks with the Jace account if [jaceKey], else opens
     * on this phone only). With a Jace account, no Secret Key (the Jace sign-in protects the synced copy).
     * Returns the new Secret Key, if one was made.
     */
    fun create(password: String?, account: JSONObject?, jaceKey: ByteArray?): String? {
        key = Crypto.rand(32); data = emptyData()
        var sk: String? = null
        if (password != null && account == null) sk = newSecretKey()
        wrap(password, sk, account, sk != null, jaceKey)
        io.updateDevice { d -> if (sk != null) d.put("secretKey", sk) else d.remove("secretKey"); d.remove("rememberedKey") }
        save()
        return sk
    }

    private fun newSecretKey(): String {
        val chars = "ABCDEFGHJKLMNPQRSTVWXYZ23456789"
        val r = Crypto.rand(26).map { chars[(it.toInt() and 255) % chars.length] }.joinToString("")
        return "J1-" + listOf(r.substring(0, 6), r.substring(6, 11), r.substring(11, 16), r.substring(16, 21), r.substring(21, 26)).joinToString("-")
    }

    fun wrap(password: String?, secretKey: String?, account: JSONObject?, useSecretKey: Boolean, jaceKey: ByteArray?) {
        val k = key ?: throw VaultError("The vault is locked.")
        val salt = Crypto.rand(16)
        val acct: Any = account ?: meta.opt("account") ?: JSONObject.NULL
        val kdf = when {
            password == null && jaceKey != null -> JSONObject().put("name", "jace").put("sub", (acct as? JSONObject)?.optString("id") ?: "")
            password == null -> JSONObject().put("name", "device")
            useSecretKey -> JSONObject().put("name", "scrypt").put("n", 131072).put("r", 8).put("p", 1)
            else -> JSONObject().put("name", "scrypt").put("n", 131072).put("r", 8).put("p", 1).put("secretKey", false)
        }
        val kek = Crypto.deriveKek(password, secretKey, salt, kdf, jaceKey, if (kdf.optString("name") == "device") deviceKey(true) else null)
        meta = JSONObject().put("format", FORMAT).put("account", acct).put("kdf", kdf).put("salt", Crypto.b64e(salt))
            .put("wrappedKey", Crypto.seal(kek, k, Crypto.AAD_KEY)).put("keyChangedAt", now())
    }

    fun setAccount(account: JSONObject?) { meta.put("account", account ?: JSONObject.NULL) }

    // ---------- saving ----------
    fun fileDict(): JSONObject {
        val d = require(); val k = key!!
        return JSONObject(meta.toString()).put("data", Crypto.seal(k, d.toString().toByteArray(), Crypto.AAD_DATA)).put("updatedAt", now())
    }

    @Synchronized fun save() { io.save(fileDict()) }

    // ---------- items ----------
    fun items(includeTrash: Boolean = false): List<JSONObject> {
        val arr = require().optJSONArray("items") ?: return emptyList()
        return (0 until arr.length()).map { arr.getJSONObject(it) }
            .filter { !it.optBoolean("purged") && (includeTrash || !it.has("deletedAt")) }
    }

    fun item(id: String) = items(true).firstOrNull { it.optString("id") == id } ?: throw VaultError("That item doesn't exist.")

    fun addItem(type: String, title: String, fields: JSONObject): JSONObject {
        val d = require(); val t = now()
        val vaultId = d.optJSONArray("vaults")?.optJSONObject(0)?.optString("id") ?: ""
        val n = JSONObject().put("id", newId()).put("type", type).put("vaultId", vaultId).put("title", title.trim().ifEmpty { "Untitled" })
            .put("favorite", false).put("tags", JSONArray()).put("fields", fields).put("passwordHistory", JSONArray())
            .put("createdAt", t).put("updatedAt", t).put("passwordChangedAt", t)
        d.getJSONArray("items").put(n)
        save()
        return n
    }

    fun updateItem(id: String, title: String?, fields: JSONObject?) {
        val it = item(id)
        if (title != null) it.put("title", title.trim().ifEmpty { "Untitled" })
        if (fields != null) {
            val old = it.optJSONObject("fields") ?: JSONObject()
            val oldPw = old.optString("password")
            // keep what this screen doesn't edit (passkeys, custom fields, …)
            val merged = JSONObject(old.toString())
            fields.keys().forEach { k -> merged.put(k, fields.get(k)) }
            if (oldPw.isNotEmpty() && merged.optString("password") != oldPw) {
                val hist = it.optJSONArray("passwordHistory") ?: JSONArray().also { h -> it.put("passwordHistory", h) }
                hist.put(JSONObject().put("password", oldPw).put("changedAt", now()))
                it.put("passwordChangedAt", now())
            }
            it.put("fields", merged)
        }
        it.put("updatedAt", now())
        save()
    }

    fun trash(id: String) { item(id).put("deletedAt", now()).put("updatedAt", now()); save() }
    fun markUsed(id: String) { item(id).put("lastUsedAt", now()).put("useCount", item(id).optInt("useCount") + 1); save() }

    // ---------- sync: newest change wins per item and vault (vault.py merge_remote) ----------
    fun merge(remote: JSONObject): Boolean {
        val d = require()
        val rd = try { JSONObject(String(Crypto.open(key!!, remote.getJSONObject("data"), Crypto.AAD_DATA))) }
        catch (e: Exception) { throw VaultError("The vault on Jace was made with a different key. Sign out of Jace or reset its copy.") }
        var changed = false
        for (coll in listOf("items", "vaults")) {
            val mine = LinkedHashMap<String, JSONObject>()
            d.optJSONArray(coll)?.let { a -> for (i in 0 until a.length()) a.getJSONObject(i).let { mine[it.optString("id")] = it } }
            rd.optJSONArray(coll)?.let { a ->
                for (i in 0 until a.length()) {
                    val r = a.getJSONObject(i); val m = mine[r.optString("id")]
                    if (m == null || r.optString("updatedAt") > m.optString("updatedAt")) { mine[r.optString("id")] = r; changed = true }
                }
            }
            d.put(coll, JSONArray(mine.values))
        }
        val gone = d.optJSONObject("deletedVaults") ?: JSONObject()
        rd.optJSONObject("deletedVaults")?.let { r -> r.keys().forEach { id -> if (r.optString(id) > gone.optString(id)) { gone.put(id, r.optString(id)); changed = true } } }
        if (gone.length() > 0) {
            d.put("deletedVaults", gone)
            val vaults = d.getJSONArray("vaults")
            val keep = (0 until vaults.length()).map { vaults.getJSONObject(it) }.filter { v -> !(gone.has(v.optString("id")) && v.optString("updatedAt") <= gone.optString(v.optString("id"))) }
            if (keep.isNotEmpty() && keep.size != vaults.length()) {
                val ids = keep.map { it.optString("id") }.toSet()
                items(true).forEach { if (it.optString("vaultId") !in ids) it.put("vaultId", keep[0].optString("id")) }
                d.put("vaults", JSONArray(keep))
            }
        }
        val rs = rd.optJSONObject("settings"); val ls = d.optJSONObject("settings")
        if (rs != null && rs.optString("updatedAt") > (ls?.optString("updatedAt") ?: "")) { d.put("settings", rs); changed = true }
        if (remote.optString("keyChangedAt") > meta.optString("keyChangedAt")) { // a newer master password from another device
            for (k in listOf("kdf", "salt", "wrappedKey", "keyChangedAt")) if (remote.has(k)) meta.put(k, remote.get(k))
            changed = true
        }
        if (changed) save()
        return changed
    }
}
