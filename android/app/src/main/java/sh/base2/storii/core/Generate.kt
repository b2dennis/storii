package sh.base2.storii.core

import java.security.SecureRandom

/** A random password with all four character classes (no look-alikes such as l/1/O/0). */
fun generatePassword(n: Int = 20): String {
    val sets = listOf("abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*.()")
    val all = sets.joinToString("")
    val r = SecureRandom()
    while (true) {
        val p = String(CharArray(n) { all[r.nextInt(all.length)] })
        if (sets.all { s -> p.any { it in s } }) return p
    }
}
