package sh.base2.storii.core

/** Card checks, as internal/vault/card.go (shared cases: testdata/cards.json). */
object Card {
    fun digits(number: String) = number.filter { it in '0'..'9' }

    fun brand(number: String): String {
        val d = digits(number)
        fun p(n: Int) = if (d.length >= n) d.substring(0, n).toInt() else -1
        return when {
            p(2) == 34 || p(2) == 37 -> "amex"
            p(3) in 300..305 || p(2) == 36 || p(2) == 38 -> "diners"
            p(4) in 3528..3589 -> "jcb"
            p(1) == 4 -> "visa"
            p(2) in 51..55 || p(4) in 2221..2720 -> "mastercard"
            p(4) == 6011 || p(2) == 65 || p(3) in 644..649 -> "discover"
            p(2) == 62 -> "unionpay"
            p(4) in listOf(5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763, 604) -> "maestro"
            else -> ""
        }
    }

    fun valid(number: String): Boolean {
        val d = digits(number)
        if (d.length !in 12..19) return false
        val sum = d.reversed().mapIndexed { i, c ->
            val n = (c - '0') * (if (i % 2 == 1) 2 else 1)
            if (n > 9) n - 9 else n
        }.sum()
        return sum % 10 == 0
    }

    fun masked(number: String) = "•••• " + digits(number).takeLast(4)

    /** "12/29", "1/30", "12/2029" or "1229" as "MM/YY"; "" if not a valid month. */
    fun normalizeExpiry(input: String): String {
        val s = input.trim().replace(" ", "")
        var (m, y) = when {
            '/' in s -> s.substringBefore('/') to s.substringAfter('/')
            s.length == 4 || s.length == 6 -> s.take(2) to s.drop(2)
            else -> return ""
        }
        if (y.length == 4) y = y.drop(2)
        val mi = m.toIntOrNull() ?: return ""
        if (y.length != 2 || y.any { !it.isDigit() } || mi !in 1..12) return ""
        return "%02d/%s".format(mi, y)
    }

    /**
     * A card typed into a form, as a card item's fields (number, cardholder, expiry, cvc), or null when the number
     * isn't a valid card number. The expiry comes from one field ("MM/YY") or a month and a year field.
     */
    fun fromForm(number: String, cardholder: String = "", month: String = "", year: String = "", expiry: String = "", cvc: String = ""): Map<String, String>? {
        if (!valid(number)) return null
        val exp = normalizeExpiry(expiry.ifBlank { if (month.isNotBlank() && year.isNotBlank()) "${month.trim()}/${year.trim().takeLast(2)}" else "" })
        return buildMap {
            put("number", digits(number))
            if (cardholder.isNotBlank()) put("cardholder", cardholder.trim())
            if (exp.isNotEmpty()) put("expiry", exp)
            if (cvc.isNotBlank()) put("cvc", cvc.trim())
        }
    }

    // Month names as they start in English, German and French ("Jan", "März", "juil.").
    private val MONTHS = listOf(
        listOf("jan"), listOf("feb", "fév", "fev"), listOf("mar", "mär", "mrz"), listOf("apr", "avr"), listOf("may", "mai"),
        listOf("jun", "juin"), listOf("jul", "juil"), listOf("aug", "aoû", "aou"), listOf("sep"), listOf("oct", "okt"),
        listOf("nov"), listOf("dec", "dez", "déc"),
    )

    /** The month a dropdown option means ("01", "1 - January", "Jan", "März") as "MM", or "". */
    fun monthOf(option: String): String {
        val s = option.trim().lowercase()
        Regex("^(\\d{1,2})(?!\\d)").find(s)?.let { m ->
            val n = m.groupValues[1].toInt()
            return if (n in 1..12) "%02d".format(n) else ""
        }
        val i = MONTHS.indexOfFirst { names -> names.any { s.startsWith(it) } }
        return if (i < 0) "" else "%02d".format(i + 1)
    }

    /** The year a dropdown option means ("2029", "29") as "YY", or "". */
    fun yearOf(option: String): String {
        val m = Regex("(?<!\\d)(\\d{4}|\\d{2})(?!\\d)").find(option.trim()) ?: return ""
        return m.groupValues[1].takeLast(2)
    }

    /** Which option of a month dropdown is month mm ("MM"); -1 when none is. */
    fun monthOption(options: List<String>, mm: String) = if (mm.isEmpty()) -1 else options.indexOfFirst { monthOf(it) == mm }

    /** Which option of a year dropdown is year yy ("YY"); -1 when none is. */
    fun yearOption(options: List<String>, yy: String) = if (yy.isEmpty()) -1 else options.indexOfFirst { yearOf(it) == yy }

    /** "Visa 4242": the name a saved card gets. */
    fun defaultName(number: String) = "${displayBrand(number).ifEmpty { "Card" }} ${digits(number).takeLast(4)}"

    fun displayBrand(number: String) = brand(number).let {
        when (it) { "amex" -> "American Express"; "jcb" -> "JCB"; "unionpay" -> "UnionPay"; else -> it.replaceFirstChar(Char::uppercase) }
    }
}
