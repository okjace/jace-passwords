package com.okjace.jacepasswords

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** The Android app must open vaults made by the desktop app, and compute exactly the same keys and codes. */
class CompatTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun fixture(name: String) = JSONObject(javaClass.classLoader!!.getResource(name)!!.readText())

    private class MemoryIO(var file: JSONObject? = null) : VaultIO {
        val dev = JSONObject()
        override fun load() = file
        override fun save(file: JSONObject?) { this.file = file }
        override fun device() = JSONObject(dev.toString())
        override fun updateDevice(change: (JSONObject) -> Unit): JSONObject { change(dev); return dev }
    }

    @Test fun scryptMatchesRfc7914() {
        val out = Crypto.scrypt("password".toByteArray(), "NaCl".toByteArray(), 1024, 8, 16, 64)
        assertEquals("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640", hex(out))
    }

    @Test fun scryptMatchesPythonAtVaultSettings() {
        val salt = ByteArray(16) { it.toByte() }
        assertEquals("cd475d58b70847320a4c5cfc0b6bf1e93cdcd602277c29a03f31533549d8e888",
            hex(Crypto.scrypt("hunter2 é".toByteArray(), salt, 131072, 8, 1, 32)))
    }

    @Test fun steamAndTotpCodesMatchPython() {
        assertEquals("2KM2P", Totp.code("steam://JBSWY3DPEHPK3PXP", 1_700_000_000_000).code)
        assertEquals("2KM2P", Totp.code("otpauth://steam/Steam:me?secret=JBSWY3DPEHPK3PXP", 1_700_000_000_000).code)
        assertEquals("324550", Totp.code("JBSWY3DPEHPK3PXP", 1_700_000_000_000).code)
    }

    @Test fun opensDesktopVaultWithSecretKey() {
        val fx = fixture("vault-secretkey.json")
        val io = MemoryIO()
        val v = Vault(io)
        v.unlock(fx.getString("password"), fx.getString("secretKey"), null, fx.getJSONObject("file"))
        assertEquals(listOf("GitHub", "Wi-Fi"), v.items().map { it.getString("title") }.sorted())
        // saved here, then opens again from this phone's copy with the remembered Secret Key
        v.lock()
        v.unlock(fx.getString("password"), null, null)
        assertTrue(v.unlocked)
    }

    @Test fun opensLinkedVaultAndRoundTrips() {
        val fx = fixture("vault-linked.json")
        val io = MemoryIO()
        val v = Vault(io)
        v.unlock(fx.getString("password"), null, null, fx.getJSONObject("file"))
        val added = v.addItem("login", "From Android", JSONObject().put("username", "a").put("password", "b"))
        v.lock()
        v.unlock(fx.getString("password"), null, null)
        assertTrue(v.items().any { it.getString("id") == added.getString("id") })
        // remembered on this phone: opens without the password
        v.remember(true); v.lock(); v.unlock(null, null, null)
        assertTrue(v.unlocked)
    }

    @Test fun mergeKeepsNewestPerItem() {
        val fx = fixture("vault-linked.json")
        val a = Vault(MemoryIO()); a.unlock(fx.getString("password"), null, null, fx.getJSONObject("file"))
        val b = Vault(MemoryIO()); b.unlock(fx.getString("password"), null, null, fx.getJSONObject("file"))
        b.addItem("note", "Only on B", JSONObject().put("body", "hi"))
        assertTrue(a.merge(b.fileDict()))
        assertTrue(a.items().any { it.getString("title") == "Only on B" })
    }

    @Test fun matchesSitesAndApps() {
        val login = JSONObject().put("type", "login").put("title", "GitHub").put("fields", JSONObject().put("urls", org.json.JSONArray().put("https://github.com/login")))
        assertEquals(2, Match.web(login, "github.com"))
        assertEquals(1, Match.web(login, "gist.github.com"))
        assertEquals(0, Match.web(login, "evilgithub.com"))
        assertEquals(1, Match.app(login, "com.github.android"))
        assertEquals("bbc.co.uk", Match.site("www.bbc.co.uk"))
    }
}
