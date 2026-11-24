package com.okjace.jacepasswords

import android.app.Application
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.security.SecureRandom

/** The one vault on this phone, shared by the app's screens and the autofill service (same process). */
class JpApp : Application() {
    lateinit var store: Store
    lateinit var vault: Vault
    val jace = Jace { token() }
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val syncLock = Mutex()

    /** Bumped on every change, so screens redraw. */
    val changes = MutableStateFlow(0)
    val syncStatus = MutableStateFlow("")

    override fun onCreate() {
        super.onCreate()
        app = this
        BuildConfigInfo.version = packageManager.getPackageInfo(packageName, 0).versionName ?: "0"
        store = Store(this)
        vault = Vault(object : VaultIO {
            override fun load() = store.vault()
            override fun save(file: JSONObject?) = store.saveVault(file)
            override fun device() = store.device()
            override fun updateDevice(change: (JSONObject) -> Unit) = store.updateDevice(change)
        })
        Updates.schedule(this)
    }

    fun changed() { changes.value++ }

    // ---------- Jace sign-in ----------
    fun token(): String? {
        val d = store.device()
        val t = d.optString("token").takeIf { it.isNotEmpty() } ?: return null
        if (d.optLong("tokenExpires") in 1 until System.currentTimeMillis()) return null
        return t
    }
    fun account(): JSONObject? = store.device().optJSONObject("user")
    fun signedIn() = token() != null

    fun newSignInState(): String {
        val s = ByteArray(24).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        store.updateDevice { it.put("signinState", s) }
        return s
    }

    /** The sign-in came back (App Link or jacepasswords://): check it's the one we started, then keep the token. */
    suspend fun finishSignIn(token: String, expiresIn: Long, appState: String): JSONObject {
        val expected = store.device().optString("signinState")
        if (expected.isEmpty() || expected != appState) throw Vault.VaultError("That sign-in didn't come from this app. Try again.")
        store.updateDevice {
            it.remove("signinState")
            it.put("token", token).put("tokenExpires", System.currentTimeMillis() + expiresIn * 1000)
        }
        val user = jace.me() ?: throw Vault.VaultError("Jace didn't accept the sign-in. Try again.")
        store.updateDevice { it.put("user", user) }
        if (vault.unlocked) { vault.setAccount(user); vault.save(); syncNow() }
        changed()
        return user
    }

    fun signOut() {
        store.updateDevice { it.remove("token"); it.remove("tokenExpires"); it.remove("user"); it.remove("syncVersion") }
        syncStatus.value = ""
        changed()
    }

    fun jaceKey(): ByteArray {
        val u = account() ?: throw Vault.VaultError("Sign in with Jace to unlock this vault.")
        return jace.vaultKey(u.getString("id"))
    }

    // ---------- opening ----------
    /** Unlocks with whatever this vault needs; password only for master-password vaults. */
    fun unlock(password: String?, secretKey: String?) {
        val f = vault.file() ?: throw Vault.VaultError("There's no vault on this phone yet.")
        val jk = if (Vault.keyMode(f) == "jace") jaceKey() else null
        vault.unlock(password, secretKey, jk)
        changed()
        scope.launch { syncNow() }
    }

    /** Opens the vault from your Jace account on this phone (first time here). */
    fun restore(password: String?, secretKey: String?) {
        val remote = fetchRemote() ?: throw Vault.VaultError("There's no vault on your Jace account yet.")
        val jk = if (Vault.keyMode(remote) == "jace") jaceKey() else null
        vault.unlock(password, secretKey, jk, remote)
        changed()
        scope.launch { syncNow() }
    }

    /** A new vault here: no master password (unlocks with your Jace account, or opens on this phone), or one. */
    fun create(password: String?): String? {
        val acct = account()
        val jk = if (password == null && acct != null) jaceKey() else null
        val sk = vault.create(password, acct, jk)
        changed()
        scope.launch { syncNow() }
        return sk
    }

    fun lock() { vault.lock(); changed() }

    /** Locks after the vault's auto-lock time without use (not when it opens without a password here). */
    fun checkAutoLock() {
        if (!vault.unlocked || vault.keyMode() != "password" || vault.remembered()) return
        val minutes = vault.data?.optJSONObject("settings")?.optInt("autoLockMinutes", 10) ?: 10
        if (minutes > 0 && System.currentTimeMillis() - vault.lastActivity > minutes * 60_000L) lock()
    }

    // ---------- sync (vault.py sync_now) ----------
    suspend fun syncNow(): String = syncLock.withLock {
        if (!signedIn() || !vault.unlocked) return@withLock syncStatus.value
        try {
            syncStatus.value = "Syncing…"
            for (tries in 0..3) {
                val (remote, version) = jace.pull()
                if (remote != null) vault.merge(remote)
                val v = jace.push(vault.fileDict(), version)
                if (v < 0 && tries < 3) continue
                store.updateDevice { it.put("syncVersion", v) }
                break
            }
            syncStatus.value = "Synced"
        } catch (e: Jace.SignedOut) {
            signOut(); syncStatus.value = "Signed out of Jace"
        } catch (e: Exception) {
            syncStatus.value = "Sync failed: ${e.message}"
        }
        changed()
        syncStatus.value
    }

    /** The vault on your Jace account, copied here still encrypted, ready to unlock. */
    fun fetchRemote(): JSONObject? = jace.pull().first

    companion object {
        lateinit var app: JpApp
        val isAtLeastS = Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
    }
}
