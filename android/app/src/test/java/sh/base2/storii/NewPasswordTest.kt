package sh.base2.storii

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.base2.storii.autofill.NewPassword
import sh.base2.storii.autofill.NewPassword.Mark.CURRENT
import sh.base2.storii.autofill.NewPassword.Mark.NEW
import sh.base2.storii.autofill.NewPassword.Mark.NONE
import sh.base2.storii.core.Entry
import sh.base2.storii.core.Item
import sh.base2.storii.core.generatePassword
import sh.base2.storii.data.Vault

class NewPasswordTest {
    @Test
    fun marks() {
        assertEquals(NEW, NewPassword.Mark.of(listOf("newPassword"), ""))
        assertEquals(NEW, NewPassword.Mark.of(emptyList(), "new-password"))
        assertEquals(CURRENT, NewPassword.Mark.of(emptyList(), "current-password"))
        // The plain "password" hint is used on signup screens too.
        assertEquals(NONE, NewPassword.Mark.of(listOf("password"), "on"))
    }

    @Test
    fun pick() {
        assertEquals(emptyList<Int>(), NewPassword.pick(listOf(NONE)))           // login
        assertEquals(listOf(0), NewPassword.pick(listOf(NEW)))                   // signup without a repeat field
        assertEquals(listOf(0, 1), NewPassword.pick(listOf(NONE, NONE)))         // password + repeat
        assertEquals(listOf(1, 2), NewPassword.pick(listOf(NONE, NONE, NONE)))   // current, new, repeat
        assertEquals(listOf(1, 2), NewPassword.pick(listOf(CURRENT, NONE, NONE)))
        assertEquals(listOf(1), NewPassword.pick(listOf(CURRENT, NONE)))
        assertEquals(listOf(1, 2), NewPassword.pick(listOf(CURRENT, NEW, NEW)))
        assertEquals(emptyList<Int>(), NewPassword.pick(listOf(CURRENT)))
        assertEquals(emptyList<Int>(), NewPassword.pick(listOf(NONE, NONE, NONE, NONE)))
    }

    private fun login(id: String, user: String, pw: String) = Entry(id, Item(kind = Item.KIND_SECRET, type = Item.PASSWORD, name = id,
        fields = buildMap { if (user.isNotEmpty()) put("username", user); put("password", pw) }))

    @Test
    fun loginToUpdate() {
        val a = login("a", "me@x", "old-a")
        val b = login("b", "", "old-b")
        // Same username: always that login.
        assertEquals("a", Vault.loginToUpdate(listOf(a, b), "me@x", "new", changed = false, current = "")?.id)
        // A reset form without a username: the login with the current password, else the site's only one.
        assertEquals("b", Vault.loginToUpdate(listOf(a, b), "", "new", changed = true, current = "old-b")?.id)
        assertEquals("a", Vault.loginToUpdate(listOf(a), "", "new", changed = true, current = "")?.id)
        assertNull(Vault.loginToUpdate(listOf(a, b), "", "new", changed = true, current = ""))
        // A plain login form without a username never overwrites anything.
        assertNull(Vault.loginToUpdate(listOf(a), "", "new", changed = false, current = ""))
    }

    @Test
    fun generated() {
        repeat(50) {
            val p = generatePassword()
            assertEquals(20, p.length)
            assertTrue(p, p.any { it.isLowerCase() } && p.any { it.isUpperCase() } && p.any { it.isDigit() } && p.any { !it.isLetterOrDigit() })
        }
    }
}
