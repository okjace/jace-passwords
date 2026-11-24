package com.okjace.jacepasswords

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Files on this phone:
 *   vault.json   the vault file (already encrypted; the same format as every other Jace Passwords copy)
 *   device.json  this phone's own settings and secrets (Jace sign-in, Secret Key, remembered key, …),
 *                encrypted with a key that lives in Android's hardware keystore and can't be copied off the phone.
 */
class Store(context: Context) {
    private val dir = context.filesDir
    private val vaultFile = File(dir, "vault.json")
    private val deviceFile = File(dir, "device.bin")

    fun vault(): JSONObject? = runCatching { JSONObject(vaultFile.readText()) }.getOrNull()
    fun saveVault(file: JSONObject?) {
        if (file == null) { vaultFile.delete(); return }
        val tmp = File(dir, "vault.json.tmp")
        tmp.writeText(file.toString())
        tmp.renameTo(vaultFile)
    }

    @Synchronized fun device(): JSONObject = runCatching {
        val raw = deviceFile.readBytes()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, keystoreKey(), GCMParameterSpec(128, raw.copyOfRange(0, 12)))
        JSONObject(String(c.doFinal(raw.copyOfRange(12, raw.size))))
    }.getOrElse { JSONObject() }

    @Synchronized fun updateDevice(change: (JSONObject) -> Unit): JSONObject {
        val d = device()
        change(d)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, keystoreKey())
        val tmp = File(dir, "device.bin.tmp")
        tmp.writeBytes(c.iv + c.doFinal(d.toString().toByteArray()))
        tmp.renameTo(deviceFile)
        return d
    }

    private fun keystoreKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build())
        return gen.generateKey()
    }

    companion object { private const val ALIAS = "jace-passwords-device" }
}
