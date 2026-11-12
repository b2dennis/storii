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

    fun displayBrand(number: String) = brand(number).let {
        when (it) { "amex" -> "American Express"; "jcb" -> "JCB"; "unionpay" -> "UnionPay"; else -> it.replaceFirstChar(Char::uppercase) }
    }
}
