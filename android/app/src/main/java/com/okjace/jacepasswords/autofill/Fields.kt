package com.okjace.jacepasswords.autofill

import android.app.assist.AssistStructure
import android.os.Parcelable
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** The sign-in boxes Android found in an app or web page, and where they came from. */
data class Fields(
    val username: AutofillId?, val password: AutofillId?, val otp: AutofillId?,
    val webDomain: String, val pkg: String,
    val usernameValue: String?, val passwordValue: String?,
) {
    val ids: Array<AutofillId> get() = listOfNotNull(username, password, otp).toTypedArray()
    val isEmpty get() = username == null && password == null && otp == null

    companion object {
        private val USER_WORDS = Regex("user|email|e-mail|login|account|identifier|phone")
        private val OTP_WORDS = Regex("otp|totp|2fa|mfa|one.?time|verification|verify|auth.?code|passcode|security.?code|sms.?code|code")
        private val NOT = Regex("search|captcha|promo|coupon|zip|postal|card|cvv|cvc")

        fun parse(structure: AssistStructure): Fields {
            data class Box(val id: AutofillId, val kind: String?, val text: Boolean, val value: String?)
            val boxes = mutableListOf<Box>()
            var domain = ""
            fun visit(n: AssistStructure.ViewNode) {
                n.webDomain?.takeIf { it.isNotEmpty() && domain.isEmpty() }?.let { domain = it }
                val id = n.autofillId
                if (id != null && n.autofillType == View.AUTOFILL_TYPE_TEXT && n.visibility == View.VISIBLE) {
                    val hints = n.autofillHints?.joinToString(" ")?.lowercase() ?: ""
                    val html = n.htmlInfo?.attributes?.joinToString(" ") { "${it.first}=${it.second}" }?.lowercase() ?: ""
                    val words = listOf(n.idEntry, n.hint, n.contentDescription?.toString(), html).joinToString(" ").lowercase()
                    val cls = n.inputType and InputType.TYPE_MASK_CLASS
                    val variation = n.inputType and InputType.TYPE_MASK_VARIATION
                    val isPassword = "password" in hints || "type=password" in html ||
                        (cls == InputType.TYPE_CLASS_TEXT && variation in listOf(InputType.TYPE_TEXT_VARIATION_PASSWORD,
                            InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD, InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD)) ||
                        (cls == InputType.TYPE_CLASS_NUMBER && (n.inputType and InputType.TYPE_NUMBER_VARIATION_PASSWORD) != 0 && "pin" in words)
                    val kind = when {
                        NOT.containsMatchIn(words) && !isPassword -> null
                        "otp" in hints || "2fa" in hints || "smsotp" in hints || "one-time-code" in html ||
                            (OTP_WORDS.containsMatchIn(words) && !isPassword && "user" !in words && "email" !in words) -> "otp"
                        isPassword -> if ("new-password" in hints || "autocomplete=new-password" in html) "new-password" else "password"
                        "username" in hints || "email" in hints || "autocomplete=username" in html || "type=email" in html ||
                            (cls == InputType.TYPE_CLASS_TEXT && variation in listOf(InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS,
                                InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS)) || USER_WORDS.containsMatchIn(words) -> "username"
                        else -> null
                    }
                    boxes += Box(id, kind, cls == InputType.TYPE_CLASS_TEXT || cls == 0 || html.isNotEmpty(), n.autofillValue?.takeIf { it.isText }?.textValue?.toString())
                }
                for (i in 0 until n.childCount) visit(n.getChildAt(i))
            }
            for (w in 0 until structure.windowNodeCount) visit(structure.getWindowNodeAt(w).rootViewNode)
            val password = boxes.firstOrNull { it.kind == "password" } ?: boxes.firstOrNull { it.kind == "new-password" }
            var username = boxes.firstOrNull { it.kind == "username" }
            if (username == null && password != null) { // the text box just before the password
                val i = boxes.indexOf(password)
                username = boxes.take(i).lastOrNull { it.kind == null && it.text }
            }
            val otp = if (password == null) boxes.firstOrNull { it.kind == "otp" } else null
            return Fields(username?.id, password?.id, otp?.id, domain, structure.activityComponent?.packageName ?: "",
                username?.value, password?.value)
        }
    }
}

/** What the autofill screen needs to know, passed to it inside an Intent. */
@kotlinx.parcelize.Parcelize
data class Request(
    val mode: String, // "unlock" (then offer logins), "pick" (choose any login), "save" (unlock, then save)
    val username: AutofillId?, val password: AutofillId?, val otp: AutofillId?,
    val webDomain: String, val pkg: String,
    val usernameValue: String? = null, val passwordValue: String? = null,
) : Parcelable {
    fun fields() = Fields(username, password, otp, webDomain, pkg, usernameValue, passwordValue)
    companion object {
        fun of(mode: String, f: Fields) = Request(mode, f.username, f.password, f.otp, f.webDomain, f.pkg, f.usernameValue, f.passwordValue)
    }
}
