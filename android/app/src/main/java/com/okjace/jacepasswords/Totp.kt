package com.okjace.jacepasswords

import java.net.URI
import java.net.URLDecoder
import org.json.JSONObject
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Two-factor codes (TOTP, RFC 6238) and Steam Guard codes, like totp.py and webvault.js. */
object Totp {
    data class Config(val secret: String, val digits: Int, val period: Int, val algorithm: String, val issuer: String, val steam: Boolean)
    data class Code(val code: String, val period: Int, val remaining: Int)

    private const val STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"
    private const val B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    private fun clean(s: String) = s.filterNot { it.isWhitespace() || it == '-' }.uppercase()

    fun parse(raw: String): Config {
        var value = raw.trim()
        if (value.startsWith("{")) { // a Steam Desktop Authenticator .maFile
            val shared = runCatching { JSONObject(value).getString("shared_secret") }.getOrNull()
                ?: throw IllegalArgumentException("That isn't a Steam Guard file (it needs a shared_secret).")
            value = "steam://" + base32Encode(Base64.getDecoder().decode(shared))
        }
        if (value.lowercase().startsWith("steam://")) return Config(clean(value.substring(8)), 5, 30, "SHA1", "Steam", true).also { base32(it.secret) }
        if (value.lowercase().startsWith("otpauth://")) {
            val u = URI(value.replace(" ", "%20"))
            val q = (u.rawQuery ?: "").split("&").filter { it.contains("=") }.associate {
                URLDecoder.decode(it.substringBefore("="), "UTF-8").lowercase() to URLDecoder.decode(it.substringAfter("="), "UTF-8")
            }
            val label = URLDecoder.decode((u.rawPath ?: "").trimStart('/'), "UTF-8")
            if (u.host.equals("steam", true) || q["encoder"].equals("steam", true)) {
                return Config(clean(q["secret"] ?: ""), 5, 30, "SHA1", "Steam", true).also { base32(it.secret) }
            }
            if (!u.host.equals("totp", true)) throw IllegalArgumentException("Only time-based (TOTP) and Steam Guard codes are supported.")
            val cfg = Config(clean(q["secret"] ?: ""), q["digits"]?.toIntOrNull() ?: 6, q["period"]?.toIntOrNull() ?: 30,
                (q["algorithm"] ?: "SHA1").uppercase(), q["issuer"] ?: label.substringBefore(":", ""), false)
            if (cfg.algorithm !in listOf("SHA1", "SHA256", "SHA512") || cfg.digits !in 6..8 || cfg.period !in 10..120) {
                throw IllegalArgumentException("Unsupported two-factor settings.")
            }
            base32(cfg.secret)
            return cfg
        }
        return Config(clean(value), 6, 30, "SHA1", "", false).also { base32(it.secret) }
    }

    private fun base32(s: String): ByteArray {
        if (s.isEmpty()) throw IllegalArgumentException("That two-factor secret is empty.")
        var bits = 0; var v = 0
        val out = java.io.ByteArrayOutputStream()
        for (c in s.trimEnd('=')) {
            val i = B32.indexOf(c)
            if (i < 0) throw IllegalArgumentException("That isn't a valid two-factor secret (it should be base32 letters A–Z and 2–7).")
            v = (v shl 5) or i; bits += 5
            if (bits >= 8) { out.write((v ushr (bits - 8)) and 255); bits -= 8 }
        }
        return out.toByteArray()
    }

    private fun base32Encode(b: ByteArray): String {
        val sb = StringBuilder(); var bits = 0; var v = 0
        for (x in b) { v = (v shl 8) or (x.toInt() and 255); bits += 8; while (bits >= 5) { sb.append(B32[(v ushr (bits - 5)) and 31]); bits -= 5 } }
        if (bits > 0) sb.append(B32[(v shl (5 - bits)) and 31])
        return sb.toString()
    }

    fun code(value: String, nowMillis: Long = System.currentTimeMillis()): Code {
        val c = parse(value)
        val now = nowMillis / 1000
        val counter = now / c.period
        val msg = ByteArray(8) { (counter ushr (8 * (7 - it))).toByte() }
        val algo = "Hmac" + c.algorithm
        val mac = Mac.getInstance(algo).apply { init(SecretKeySpec(base32(c.secret), algo)) }.doFinal(msg)
        val off = mac[mac.size - 1].toInt() and 15
        var full = ((mac[off].toInt() and 0x7f) shl 24) or ((mac[off + 1].toInt() and 255) shl 16) or
            ((mac[off + 2].toInt() and 255) shl 8) or (mac[off + 3].toInt() and 255)
        val text = if (c.steam) {
            val sb = StringBuilder()
            repeat(5) { sb.append(STEAM_CHARS[full % STEAM_CHARS.length]); full /= STEAM_CHARS.length }
            sb.toString()
        } else {
            var p = 1; repeat(c.digits) { p *= 10 }
            (full % p).toString().padStart(c.digits, '0')
        }
        return Code(text, c.period, (c.period - (now % c.period)).toInt())
    }
}
