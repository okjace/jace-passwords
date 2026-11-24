package com.okjace.jacepasswords

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import kotlinx.coroutines.flow.MutableStateFlow
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * Updates from GitHub releases, like the desktop app: the newest JacePasswords-<v>-android.apk, checked against
 * GitHub's SHA-256, installed with one tap, or by itself with "Update automatically" (Android 12+ lets the app
 * update itself without asking once it has installed an update before; older Android asks each time).
 */
object Updates {
    data class State(val message: String = "", val ready: Boolean = false, val version: String = "")
    val state = MutableStateFlow(State())
    private const val REPO = "okjace/jace-passwords"
    private const val CHANNEL = "updates"

    private fun prefs(ctx: Context) = ctx.getSharedPreferences("jp", Context.MODE_PRIVATE)
    fun autoUpdate(ctx: Context) = prefs(ctx).getBoolean("autoUpdate", true)
    fun setAutoUpdate(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean("autoUpdate", on).apply()

    fun schedule(ctx: Context) {
        val work = PeriodicWorkRequestBuilder<UpdateWorker>(12, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build()).build()
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork("updates", ExistingPeriodicWorkPolicy.KEEP, work)
    }

    private fun newer(a: String, b: String): Boolean {
        val x = a.split(".").map { it.toIntOrNull() ?: 0 }; val y = b.split(".").map { it.toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(x.size, y.size)) { val d = (x.getOrElse(i) { 0 }) - (y.getOrElse(i) { 0 }); if (d != 0) return d > 0 }
        return false
    }

    private fun apk(ctx: Context, v: String) = File(File(ctx.filesDir, "updates").apply { mkdirs() }, "JacePasswords-$v-android.apk")

    /** Looks for a newer release; with download = true, also fetches and checks it. */
    fun check(ctx: Context, download: Boolean): State {
        val current = BuildConfigInfo.version
        return try {
            val c = URL("https://api.github.com/repos/$REPO/releases/latest").openConnection() as HttpURLConnection
            c.setRequestProperty("Accept", "application/vnd.github+json")
            c.setRequestProperty("User-Agent", "JacePasswords-Android/$current")
            val rel = JSONObject(c.inputStream.bufferedReader().use { it.readText() })
            val v = rel.optString("tag_name").removePrefix("v")
            if (!newer(v, current)) return State("You have the latest version.").also { state.value = it }
            val assets = rel.optJSONArray("assets")
            val asset = (0 until (assets?.length() ?: 0)).map { assets!!.getJSONObject(it) }.firstOrNull { it.optString("name") == "JacePasswords-$v-android.apk" }
                ?: return State("Version $v is out, but without an Android download yet.").also { state.value = it }
            val file = apk(ctx, v)
            if (!file.exists()) {
                if (!download) return State("Version $v is available.", false, v).also { state.value = it }
                state.value = State("Downloading $v…", false, v)
                val part = File(file.path + ".part")
                val d = URL(asset.getString("browser_download_url")).openConnection() as HttpURLConnection
                d.setRequestProperty("User-Agent", "JacePasswords-Android/$current")
                val md = MessageDigest.getInstance("SHA-256")
                d.inputStream.use { inp -> part.outputStream().use { out ->
                    val buf = ByteArray(1 shl 16)
                    while (true) { val n = inp.read(buf); if (n < 0) break; md.update(buf, 0, n); out.write(buf, 0, n) }
                } }
                val want = asset.optString("digest").removePrefix("sha256:")
                val got = md.digest().joinToString("") { "%02x".format(it) }
                if (want.isNotEmpty() && want != got) { part.delete(); return State("The download didn't match GitHub's checksum. Try again later.").also { state.value = it } }
                part.renameTo(file)
            }
            State("Version $v is ready to install.", true, v).also { state.value = it }
        } catch (e: Exception) {
            State("Couldn't check for updates (${e.message}).").also { state.value = it }
        }
    }

    /** Installs the downloaded update (asks Android for permission to install updates the first time). */
    fun install(ctx: Context) {
        val v = state.value.version.ifEmpty { return }
        val file = apk(ctx, v)
        if (!file.exists()) return
        if (!ctx.packageManager.canRequestPackageInstalls()) {
            ctx.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            return
        }
        val pi = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(ctx.packageName)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val id = pi.createSession(params)
        pi.openSession(id).use { s ->
            s.openWrite("base.apk", 0, file.length()).use { out -> file.inputStream().use { it.copyTo(out) }; s.fsync(out) }
            val done = PendingIntent.getBroadcast(ctx, id, Intent(ctx, InstallReceiver::class.java), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
            s.commit(done.intentSender)
        }
        state.value = State("Installing $v…", false, v)
    }

    fun notifyReady(ctx: Context, v: String) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) nm.createNotificationChannel(NotificationChannel(CHANNEL, "Updates", NotificationManager.IMPORTANCE_DEFAULT))
        if (Build.VERSION.SDK_INT >= 33 && ContextCompat.checkSelfPermission(ctx, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val open = PendingIntent.getActivity(ctx, 0, Intent(ctx, MainActivity::class.java).setAction(MainActivity.ACTION_INSTALL_UPDATE)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK), PendingIntent.FLAG_IMMUTABLE)
        nm.notify(1, NotificationCompat.Builder(ctx, CHANNEL).setSmallIcon(R.drawable.ic_notification)
            .setContentTitle("Jace Passwords $v is ready").setContentText("Tap to install the update.")
            .setContentIntent(open).setAutoCancel(true).build())
    }
}

/** Every 12 hours: download a new version; install it by itself with "Update automatically", else notify. */
class UpdateWorker(ctx: Context, params: WorkerParameters) : CoroutineWorker(ctx, params) {
    override suspend fun doWork(): Result {
        val s = Updates.check(applicationContext, download = true)
        if (!s.ready) return Result.success()
        if (Updates.autoUpdate(applicationContext) && applicationContext.packageManager.canRequestPackageInstalls()) {
            runCatching { Updates.install(applicationContext) }.onFailure { Updates.notifyReady(applicationContext, s.version) }
        } else Updates.notifyReady(applicationContext, s.version)
        return Result.success()
    }
}

/** The installer's answer: if Android wants you to confirm, show its screen (or a notification from the background). */
class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        when (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                @Suppress("DEPRECATION") val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT) ?: return
                try { ctx.startActivity(confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) }
                catch (e: Exception) { Updates.notifyReady(ctx, Updates.state.value.version) }
            }
            PackageInstaller.STATUS_SUCCESS -> Updates.state.value = Updates.State("Updated.")
            else -> Updates.state.value = Updates.State("The update didn't install: ${intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: "unknown error"}.")
        }
    }
}
