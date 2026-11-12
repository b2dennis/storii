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
    val card: Map<CardField, AutofillId> = emptyMap(),
    /** "New password" and "repeat password" fields (signup, reset, change password). */
    val newPasswords: List<AutofillId> = emptyList(),
    val newPasswordValue: String = "",
) {
    val ids get() = (listOfNotNull(username, password, otp) + newPasswords + card.values).distinct()
    val hasCard get() = CardField.NUMBER in card
    /** What a submitted form should save: the new password where there is one. */
    val savedPassword get() = newPasswordValue.ifEmpty { passwordValue }
    val isEmpty get() = ids.isEmpty()
}

private val OTP_WORDS = Regex("one.?time|otp|totp|2fa|mfa|two.?factor|verification.?code|auth(entication)?.?code|security.?code|passcode", RegexOption.IGNORE_CASE)
private val USER_WORDS = Regex("user|login|e-?mail|account|identifier", RegexOption.IGNORE_CASE)
private val PASS_WORDS = Regex("pass(word|wd)?|pwd|pin", RegexOption.IGNORE_CASE)

private enum class Kind { USERNAME, PASSWORD, OTP, TEXT, CARD }

/** Card fields: Android's autofill hints, the web's autocomplete="cc-*", then ids and labels (as the extension). */
enum class CardField(val hint: String, val autocomplete: String, val words: Regex) {
    NUMBER(View.AUTOFILL_HINT_CREDIT_CARD_NUMBER, "cc-number", Regex("card.?num|cc.?num|cardnumber|kartennummer|num(é|e)ro.?(de.?)?carte", RegexOption.IGNORE_CASE)),
    NAME("creditCardHolderName", "cc-name", Regex("card.?holder|name.?on.?card|cc.?name|karteninhaber|titulaire", RegexOption.IGNORE_CASE)),
    MONTH(View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_MONTH, "cc-exp-month", Regex("exp\\w*.?(month|mm\\b)|ablaufmonat", RegexOption.IGNORE_CASE)),
    YEAR(View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_YEAR, "cc-exp-year", Regex("exp\\w*.?(year|yy)|ablaufjahr", RegexOption.IGNORE_CASE)),
    CVC(View.AUTOFILL_HINT_CREDIT_CARD_SECURITY_CODE, "cc-csc", Regex("cvc|cvv|csc|security.?code|card.?code|sicherheitscode|pr(ü|u)fnummer", RegexOption.IGNORE_CASE)),
    EXPIRY(View.AUTOFILL_HINT_CREDIT_CARD_EXPIRATION_DATE, "cc-exp", Regex("(?<![a-z])exp(iry|iration|ires)?(\\b|[_-]?date)|expir|mm.?/.?yy|ablaufdatum|g(ü|u)ltig.?bis", RegexOption.IGNORE_CASE)),
}

/** Walks an AssistStructure (app views or a browser's web page) and classifies the text inputs. */
object Parser {
    fun parse(structure: AssistStructure): ParsedScreen {
        val nodes = mutableListOf<Pair<AssistStructure.ViewNode, Kind>>()
        val card = linkedMapOf<CardField, AutofillId>()
        var webDomain: String? = null
        fun walk(n: AssistStructure.ViewNode) {
            if (webDomain == null && !n.webDomain.isNullOrBlank()) webDomain = n.webDomain
            if (n.autofillId != null && n.autofillType == View.AUTOFILL_TYPE_TEXT && n.visibility == View.VISIBLE) {
                val c = cardField(n)
                if (c != null) card.putIfAbsent(c, n.autofillId!!) else classify(n)?.let { nodes += n to it }
            }
            for (i in 0 until n.childCount) walk(n.getChildAt(i))
        }
        for (i in 0 until structure.windowNodeCount) walk(structure.getWindowNodeAt(i).rootViewNode)

        val passwords = nodes.filter { it.second == Kind.PASSWORD }
        val fresh = NewPassword.pick(passwords.map { NewPassword.Mark.of(hints(it.first), autocomplete(it.first)) })
            .map { passwords[it] }
        val password = passwords.firstOrNull { it !in fresh }
        val otp = nodes.firstOrNull { it.second == Kind.OTP }
        val username = nodes.firstOrNull { it.second == Kind.USERNAME }
            ?: (password ?: fresh.firstOrNull())?.let { pw -> nodes.takeWhile { it !== pw }.lastOrNull { it.second == Kind.TEXT } }
            ?: nodes.singleOrNull()?.takeIf { it.second == Kind.TEXT && USER_WORDS.containsMatchIn(describe(it.first)) }
        return ParsedScreen(
            packageName = structure.activityComponent?.packageName.orEmpty(),
            webDomain = webDomain,
            username = username?.first?.autofillId,
            password = password?.first?.autofillId,
            otp = otp?.first?.autofillId,
            usernameValue = username?.first?.let(::value).orEmpty(),
            passwordValue = password?.first?.let(::value).orEmpty(),
            newPasswords = fresh.mapNotNull { it.first.autofillId },
            newPasswordValue = fresh.firstOrNull()?.first?.let(::value).orEmpty(),
            // A lone "security code" without a card number is a 2FA field, not a card.
            card = if (CardField.NUMBER in card) card else emptyMap(),
        ).let { s -> if (s.hasCard || CardField.CVC !in card) s else s.copy(otp = s.otp ?: card[CardField.CVC]) }
    }

    private fun value(n: AssistStructure.ViewNode) = n.autofillValue?.takeIf { it.isText }?.textValue?.toString()
    private fun hints(n: AssistStructure.ViewNode) = n.autofillHints.orEmpty().toList()
    private fun autocomplete(n: AssistStructure.ViewNode) =
        n.htmlInfo?.attributes?.firstOrNull { it.first == "autocomplete" }?.second?.lowercase().orEmpty()

    private fun cardField(n: AssistStructure.ViewNode): CardField? {
        val html = n.htmlInfo
        if (html != null && html.tag.lowercase() != "input") return null
        val hints = n.autofillHints.orEmpty().toSet()
        val autocomplete = html?.attributes?.firstOrNull { it.first == "autocomplete" }?.second?.lowercase()?.split(' ')?.last().orEmpty()
        CardField.entries.firstOrNull { it.hint in hints || it.autocomplete == autocomplete }?.let { return it }
        if (hints.isNotEmpty() || (autocomplete.isNotEmpty() && autocomplete != "on" && autocomplete != "off")) return null
        val text = describe(n)
        return CardField.entries.firstOrNull { it.words.containsMatchIn(text) }
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

/**
 * Which password fields want a new password. Marked ones (hint "newPassword", autocomplete="new-password") decide when
 * present. Otherwise: one field is a login; two are "password + repeat" (signup, reset); three are "current, new,
 * repeat". A field marked as the current password never is.
 */
object NewPassword {
    enum class Mark { NEW, CURRENT, NONE;
        companion object {
            fun of(hints: List<String>, autocomplete: String): Mark = when {
                hints.any { it.equals("newPassword", true) } || "new-password" in autocomplete -> NEW
                "current-password" in autocomplete -> CURRENT
                else -> NONE
            }
        }
    }

    fun pick(fields: List<Mark>): List<Int> {
        val marked = fields.indices.filter { fields[it] == Mark.NEW }
        if (marked.isNotEmpty()) return marked
        val open = fields.indices.filter { fields[it] == Mark.NONE }
        return when {
            fields.size == 2 && open.size == 2 -> open
            fields.size == 3 -> open.takeLast(2).takeIf { it.size == 2 }.orEmpty()
            fields.size == 2 && open.size == 1 && fields.count { it == Mark.CURRENT } == 1 -> open
            else -> emptyList()
        }
    }
}
