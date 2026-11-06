package sh.base2.storii.autofill

import android.app.assist.AssistStructure
import android.text.InputType
import android.view.View
import android.view.autofill.AutofillId

/** The fields of a screen storii can fill, and who it belongs to. */
data class ParsedScreen(
    val packageName: String,
    val webDomain: String?,
    val username: AutofillId?,
    val password: AutofillId?,
    val otp: AutofillId?,
    val usernameValue: String = "",
    val passwordValue: String = "",
) {
    val ids get() = listOfNotNull(username, password, otp)
    val isEmpty get() = ids.isEmpty()
}

private val OTP_WORDS = Regex("one.?time|otp|totp|2fa|mfa|two.?factor|verification.?code|auth(entication)?.?code|security.?code|passcode", RegexOption.IGNORE_CASE)
private val USER_WORDS = Regex("user|login|e-?mail|account|identifier", RegexOption.IGNORE_CASE)
private val PASS_WORDS = Regex("pass(word|wd)?|pwd|pin", RegexOption.IGNORE_CASE)

private enum class Kind { USERNAME, PASSWORD, OTP, TEXT }

/** Walks an AssistStructure (app views or a browser's web page) and classifies the text inputs. */
object Parser {
    fun parse(structure: AssistStructure): ParsedScreen {
        val nodes = mutableListOf<Pair<AssistStructure.ViewNode, Kind>>()
        var webDomain: String? = null
        fun walk(n: AssistStructure.ViewNode) {
            if (webDomain == null && !n.webDomain.isNullOrBlank()) webDomain = n.webDomain
            if (n.autofillId != null && n.autofillType == View.AUTOFILL_TYPE_TEXT && n.visibility == View.VISIBLE) {
                classify(n)?.let { nodes += n to it }
            }
            for (i in 0 until n.childCount) walk(n.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)

        val password = nodes.firstOrNull { it.second == Kind.PASSWORD }
        val otp = nodes.firstOrNull { it.second == Kind.OTP }
        val username = nodes.firstOrNull { it.second == Kind.USERNAME }
            ?: password?.let { pw -> nodes.takeWhile { it !== pw }.lastOrNull { it.second == Kind.TEXT } }
            ?: nodes.singleOrNull()?.takeIf { it.second == Kind.TEXT && USER_WORDS.containsMatchIn(describe(it.first)) }
        return ParsedScreen(
            packageName = structure.activityComponent?.packageName.orEmpty(),
            webDomain = webDomain,
            username = username?.first?.autofillId,
            password = password?.first?.autofillId,
            otp = otp?.first?.autofillId,
            usernameValue = username?.first?.autofillValue?.takeIf { it.isText }?.textValue?.toString().orEmpty(),
            passwordValue = password?.first?.autofillValue?.takeIf { it.isText }?.textValue?.toString().orEmpty(),
        )
    }

    private fun describe(n: AssistStructure.ViewNode): String {
        val attrs = n.htmlInfo?.attributes?.joinToString(" ") { "${it.first}=${it.second}" }.orEmpty()
        return listOfNotNull(n.idEntry, n.hint, n.contentDescription?.toString(), attrs).joinToString(" ")
    }

    private fun classify(n: AssistStructure.ViewNode): Kind? {
        val hints = n.autofillHints.orEmpty().map { it.lowercase() }
        val html = n.htmlInfo
        if (html != null && html.tag.lowercase() != "input") return null
        val htmlType = html?.attributes?.firstOrNull { it.first == "type" }?.second?.lowercase()
        val autocomplete = html?.attributes?.firstOrNull { it.first == "autocomplete" }?.second?.lowercase().orEmpty()
        if (htmlType != null && htmlType !in setOf("text", "email", "tel", "password", "number")) return null
        val text = describe(n)

        if (hints.any { "otp" in it || "one-time" in it } || "one-time-code" in autocomplete) return Kind.OTP
        if (hints.any { "password" in it } || "password" in autocomplete) return Kind.PASSWORD
        if (hints.any { it in setOf("username", "emailaddress", "email") || "username" in it } ||
            "username" in autocomplete || autocomplete == "email") return Kind.USERNAME

        val variation = n.inputType and InputType.TYPE_MASK_VARIATION
        val cls = n.inputType and InputType.TYPE_MASK_CLASS
        val isPasswordInput = htmlType == "password" || (cls == InputType.TYPE_CLASS_TEXT && variation in setOf(
            InputType.TYPE_TEXT_VARIATION_PASSWORD, InputType.TYPE_TEXT_VARIATION_WEB_PASSWORD, InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD,
        )) || (cls == InputType.TYPE_CLASS_NUMBER && variation == InputType.TYPE_NUMBER_VARIATION_PASSWORD)
        if (OTP_WORDS.containsMatchIn(text) && !Regex("password", RegexOption.IGNORE_CASE).containsMatchIn(text)) return Kind.OTP
        if (isPasswordInput) return Kind.PASSWORD
        if (htmlType == "email" || (cls == InputType.TYPE_CLASS_TEXT && variation in setOf(
                InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS, InputType.TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS,
            ))) return Kind.USERNAME
        if (USER_WORDS.containsMatchIn(text) && !PASS_WORDS.containsMatchIn(text)) return Kind.USERNAME
        if (cls == InputType.TYPE_CLASS_TEXT || htmlType == "text" || htmlType == "tel") return Kind.TEXT
        return null
    }
}
