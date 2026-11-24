package com.okjace.jacepasswords

import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The vault's cryptography, byte for byte the same as the desktop app (jace_passwords/crypto.py) and the web
 * engine (webvault.js): scrypt(N=2^17, r=8, p=1) of the master password, XOR an HKDF of the Secret Key, unwraps a
 * random 256-bit vault key; AES-256-GCM with fixed associated data seals the key and the vault.
 */
object Crypto {
    class CryptoError(message: String) : Exception(message)

    val AAD_KEY = "jace-passwords:key".toByteArray()
    val AAD_DATA = "jace-passwords:data".toByteArray()
    val AAD_REMEMBER = "jace-passwords:remembered".toByteArray()
    private const val B32 = "ABCDEFGHJKLMNPQRSTVWXYZ23456789"
    private val random = SecureRandom()

    fun rand(n: Int) = ByteArray(n).also { random.nextBytes(it) }
    fun b64e(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
    fun b64d(s: String): ByteArray = Base64.getDecoder().decode(s)

    // ---------- AES-256-GCM: {"iv": b64, "ct": b64 (ciphertext + 16-byte tag)} ----------
    fun seal(key: ByteArray, plain: ByteArray, aad: ByteArray): JSONObject {
        val iv = rand(12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        c.updateAAD(aad)
        return JSONObject().put("iv", b64e(iv)).put("ct", b64e(c.doFinal(plain)))
    }

    fun open(key: ByteArray, box: JSONObject, aad: ByteArray): ByteArray = try {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, b64d(box.getString("iv"))))
        c.updateAAD(aad)
        c.doFinal(b64d(box.getString("ct")))
    } catch (e: Exception) {
        throw CryptoError("Wrong master password or Secret Key.")
    }

    // ---------- HMAC / HKDF-SHA256 / PBKDF2 ----------
    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        m.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        parts.forEach { m.update(it) }
        return m.doFinal()
    }

    /** HKDF-SHA256 with a 32-byte output (one expand block), as in crypto.py. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String): ByteArray {
        val prk = hmac(salt, ikm)
        return hmac(prk, info.toByteArray(), byteArrayOf(1))
    }

    private fun pbkdf2Once(pass: ByteArray, salt: ByteArray, len: Int): ByteArray {
        val m = Mac.getInstance("HmacSHA256")
        // HMAC with an empty password is allowed by the spec; Java's SecretKeySpec isn't, so pad as HMAC would.
        m.init(SecretKeySpec(if (pass.isEmpty()) ByteArray(64) else pass, "HmacSHA256"))
        val out = ByteArray(len)
        var block = 1
        var off = 0
        while (off < len) {
            m.update(salt)
            m.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
            val t = m.doFinal()
            System.arraycopy(t, 0, out, off, minOf(32, len - off))
            off += 32
            block++
        }
        return out
    }

    // ---------- scrypt (RFC 7914) ----------
    fun scrypt(pass: ByteArray, salt: ByteArray, n: Int, r: Int, p: Int, dkLen: Int): ByteArray {
        require(n > 1 && n and (n - 1) == 0) { "N must be a power of 2" }
        val b = pbkdf2Once(pass, salt, p * 128 * r)
        val xy = IntArray(64 * r)
        val v = IntArray(32 * r * n)
        for (i in 0 until p) smix(b, i * 128 * r, r, n, v, xy)
        return pbkdf2Once(pass, b, dkLen)
    }

    private fun smix(b: ByteArray, bi: Int, r: Int, n: Int, v: IntArray, xy: IntArray) {
        val words = 32 * r
        for (k in 0 until words) {
            val o = bi + k * 4
            xy[k] = (b[o].toInt() and 255) or ((b[o + 1].toInt() and 255) shl 8) or
                ((b[o + 2].toInt() and 255) shl 16) or ((b[o + 3].toInt() and 255) shl 24)
        }
        for (i in 0 until n) {
            System.arraycopy(xy, 0, v, i * words, words)
            blockMix(xy, r)
        }
        for (i in 0 until n) {
            val j = xy[(2 * r - 1) * 16] and (n - 1)
            val vo = j * words
            for (k in 0 until words) xy[k] = xy[k] xor v[vo + k]
            blockMix(xy, r)
        }
        for (k in 0 until words) {
            val w = xy[k]
            val o = bi + k * 4
            b[o] = w.toByte(); b[o + 1] = (w ushr 8).toByte(); b[o + 2] = (w ushr 16).toByte(); b[o + 3] = (w ushr 24).toByte()
        }
    }

    // xy holds B (words 0..32r) and scratch Y (words 32r..64r)
    private val xBuf = ThreadLocal.withInitial { IntArray(16) }
    private fun blockMix(xy: IntArray, r: Int) {
        val x = xBuf.get()!!
        val y = 32 * r
        System.arraycopy(xy, (2 * r - 1) * 16, x, 0, 16)
        for (i in 0 until 2 * r) {
            for (k in 0 until 16) x[k] = x[k] xor xy[i * 16 + k]
            salsa8(x)
            System.arraycopy(x, 0, xy, y + i * 16, 16)
        }
        for (i in 0 until r) System.arraycopy(xy, y + (2 * i) * 16, xy, i * 16, 16)
        for (i in 0 until r) System.arraycopy(xy, y + (2 * i + 1) * 16, xy, (i + r) * 16, 16)
    }

    private fun salsa8(b: IntArray) {
        var x0 = b[0]; var x1 = b[1]; var x2 = b[2]; var x3 = b[3]; var x4 = b[4]; var x5 = b[5]; var x6 = b[6]; var x7 = b[7]
        var x8 = b[8]; var x9 = b[9]; var x10 = b[10]; var x11 = b[11]; var x12 = b[12]; var x13 = b[13]; var x14 = b[14]; var x15 = b[15]
        fun rl(a: Int, s: Int) = (a shl s) or (a ushr (32 - s))
        for (i in 0 until 4) {
            x4 = x4 xor rl(x0 + x12, 7); x8 = x8 xor rl(x4 + x0, 9); x12 = x12 xor rl(x8 + x4, 13); x0 = x0 xor rl(x12 + x8, 18)
            x9 = x9 xor rl(x5 + x1, 7); x13 = x13 xor rl(x9 + x5, 9); x1 = x1 xor rl(x13 + x9, 13); x5 = x5 xor rl(x1 + x13, 18)
            x14 = x14 xor rl(x10 + x6, 7); x2 = x2 xor rl(x14 + x10, 9); x6 = x6 xor rl(x2 + x14, 13); x10 = x10 xor rl(x6 + x2, 18)
            x3 = x3 xor rl(x15 + x11, 7); x7 = x7 xor rl(x3 + x15, 9); x11 = x11 xor rl(x7 + x3, 13); x15 = x15 xor rl(x11 + x7, 18)
            x1 = x1 xor rl(x0 + x3, 7); x2 = x2 xor rl(x1 + x0, 9); x3 = x3 xor rl(x2 + x1, 13); x0 = x0 xor rl(x3 + x2, 18)
            x6 = x6 xor rl(x5 + x4, 7); x7 = x7 xor rl(x6 + x5, 9); x4 = x4 xor rl(x7 + x6, 13); x5 = x5 xor rl(x4 + x7, 18)
            x11 = x11 xor rl(x10 + x9, 7); x8 = x8 xor rl(x11 + x10, 9); x9 = x9 xor rl(x8 + x11, 13); x10 = x10 xor rl(x9 + x8, 18)
            x12 = x12 xor rl(x15 + x14, 7); x13 = x13 xor rl(x12 + x15, 9); x14 = x14 xor rl(x13 + x12, 13); x15 = x15 xor rl(x14 + x13, 18)
        }
        b[0] += x0; b[1] += x1; b[2] += x2; b[3] += x3; b[4] += x4; b[5] += x5; b[6] += x6; b[7] += x7
        b[8] += x8; b[9] += x9; b[10] += x10; b[11] += x11; b[12] += x12; b[13] += x13; b[14] += x14; b[15] += x15
    }

    // ---------- the key that unwraps the vault key (crypto.py derive_kek) ----------
    fun normalizeSecretKey(sk: String): String {
        var raw = sk.uppercase().filter { it.isLetterOrDigit() }
        if (raw.startsWith("J1")) raw = raw.substring(2)
        if (raw.length != 26 || raw.any { it !in B32 }) {
            throw CryptoError("That Secret Key doesn't look right. It starts with J1- and has 26 more letters and numbers.")
        }
        return raw
    }

    fun deriveKek(password: String?, secretKey: String?, salt: ByteArray, kdf: JSONObject, jaceKey: ByteArray?, deviceKey: ByteArray?): ByteArray {
        when (kdf.optString("name")) {
            "device" -> return hkdf(deviceKey ?: throw CryptoError("This vault opens only on the device that made it."), salt, "jace-passwords device unlock v1")
            "jace" -> return hkdf(jaceKey ?: throw CryptoError("Sign in with Jace to unlock this vault."), salt, "jace-passwords jace unlock v1")
            "scrypt" -> {}
            else -> throw CryptoError("Unknown key derivation.")
        }
        val k1 = scrypt((password ?: "").toByteArray(Charsets.UTF_8), salt, kdf.getInt("n"), kdf.getInt("r"), kdf.getInt("p"), 32)
        if (kdf.has("secretKey") && !kdf.optBoolean("secretKey", true)) return k1
        val k2 = hkdf(normalizeSecretKey(secretKey ?: throw CryptoError("Enter your Secret Key (it's on your Emergency Kit).")).toByteArray(), salt, "jace-passwords secret key v1")
        return ByteArray(32) { (k1[it].toInt() xor k2[it].toInt()).toByte() }
    }
}
