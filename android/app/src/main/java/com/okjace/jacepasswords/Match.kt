package com.okjace.jacepasswords

import org.json.JSONObject
import java.net.URI
import java.security.SecureRandom

/** Which saved logins belong to a website or an Android app (security.py matches, plus app package names). */
object Match {
    private val MULTI = setOf("co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.in", "co.za",
        "com.br", "com.mx", "com.cn", "com.hk", "com.sg", "com.tr", "github.io", "vercel.app", "netlify.app", "pages.dev", "herokuapp.com")

    fun host(url: String): String = runCatching {
        val u = if ("://" in url) url else "https://$url"
        (URI(u).host ?: "").lowercase().removePrefix("www.")
    }.getOrDefault("")

    /** "accounts.google.com" -> "google.com"; "bbc.co.uk" stays. */
    fun site(host: String): String {
        val parts = host.lowercase().removePrefix("www.").split(".").filter { it.isNotEmpty() }
        if (parts.size <= 2) return parts.joinToString(".")
        val last2 = parts.takeLast(2).joinToString(".")
        return if (last2 in MULTI) parts.takeLast(3).joinToString(".") else last2
    }

    private fun urls(item: JSONObject): List<String> {
        val a = item.optJSONObject("fields")?.optJSONArray("urls") ?: return emptyList()
        return (0 until a.length()).map { a.optString(it) }
    }

    /** 2 = same host, 1 = same site, 0 = no. */
    fun web(item: JSONObject, domain: String): Int {
        if (item.optString("type") != "login" || domain.isEmpty()) return 0
        val h = host(domain); val s = site(h)
        var best = 0
        for (u in urls(item)) {
            val uh = host(u)
            if (uh == h) return 2
            if (uh.isNotEmpty() && site(uh) == s) best = 1
        }
        return best
    }

    /** An Android app: an "androidapp://package" website on the login, or the app's name in the login's site. */
    fun app(item: JSONObject, pkg: String): Int {
        if (item.optString("type") != "login" || pkg.isEmpty()) return 0
        val us = urls(item)
        if (us.any { it.equals("androidapp://$pkg", true) }) return 2
        val words = pkg.lowercase().split(".").filter { it.length > 2 && it !in setOf("com", "org", "net", "app", "android", "mobile", "apps", "client") }
        for (u in us) {
            val label = site(host(u)).substringBefore(".")
            if (label.length > 2 && words.any { it == label || it.startsWith(label) }) return 1
        }
        val title = item.optString("title").lowercase().filter { it.isLetterOrDigit() }
        return if (title.length > 2 && words.any { it == title }) 1 else 0
    }

    private val rng = SecureRandom()
    fun password(length: Int = 20): String {
        val sets = listOf("abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+?")
        val all = sets.joinToString("")
        val chars = sets.map { it[rng.nextInt(it.length)] }.toMutableList()
        while (chars.size < length) chars.add(all[rng.nextInt(all.length)])
        chars.shuffle(rng)
        return chars.joinToString("")
    }
}
