package sh.base2.storii

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.base2.storii.core.Backup
import sh.base2.storii.core.Crypto
import sh.base2.storii.core.StoriiJson
import java.io.File

/** testdata/backup.json, shared with internal/vault/backup_test.go. */
class BackupTest {
    private val v = StoriiJson.parseToJsonElement(File("../../testdata/backup.json").readText()).jsonObject
    private val password = v["password"]!!.toString().trim('"')
    private val items = v["items"]!!.jsonObject
    private val file = v["file"]!!.toString()

    @Test fun opensTheSharedBackup() {
        assertTrue(Backup.isBackup(file))
        assertFalse(Backup.isBackup("""{"items":[]}"""))
        assertFalse(Backup.isBackup("url,username"))
        assertEquals(items.toMap(), Backup.open(password, file))
        assertThrows(Backup.WrongPassword::class.java) { Backup.open("wrong", file) }
    }

    @Test fun roundTripAndPlan() {
        val again = Backup.seal("other pw", items, Crypto.newKdf().copy(iterations = 1, memoryKib = 16384, parallelism = 1))
        assertEquals(items.toMap(), Backup.open("other pw", again))
        val ids = items.keys.sorted()
        val plan = Backup.plan(items + ("nope" to JsonObject(emptyMap())), setOf(ids[0]))
        assertEquals(ids.drop(1).toSet(), plan.add.map { it.first }.toSet())
        assertEquals(2, plan.skipped)
    }
}
