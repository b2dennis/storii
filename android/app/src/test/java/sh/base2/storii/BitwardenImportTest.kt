package sh.base2.storii

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.base2.storii.core.BitwardenImport
import java.io.File

/** testdata/import/bitwarden*.json, shared with internal/importer/bitwarden_test.go. */
class BitwardenImportTest {
    private val text = File("../../testdata/import/bitwarden.json").readText()

    @Test fun sharedCases() {
        assertTrue(BitwardenImport.detect(text))
        checkCases(BitwardenImport.parse(text), "bitwarden-cases.json")
    }

    @Test fun encrypted() {
        val enc = """{"encrypted": true, "passwordProtected": true, "data": "2.abc"}"""
        assertTrue(BitwardenImport.detect(enc))
        assertThrows(BitwardenImport.Encrypted::class.java) { BitwardenImport.parse(enc) }
        assertFalse(BitwardenImport.detect("name,url,username,password\n"))
        assertFalse(BitwardenImport.detect("""{"services": []}"""))
    }
}
