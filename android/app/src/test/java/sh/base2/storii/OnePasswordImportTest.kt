package sh.base2.storii

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import sh.base2.storii.core.BitwardenImport
import sh.base2.storii.core.OnePasswordImport
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** testdata/import/1password*.json, shared with internal/importer/onepassword_test.go. */
class OnePasswordImportTest {
    private val text = File("../../testdata/import/1password.json").readText()

    @Test fun sharedCases() {
        assertTrue(OnePasswordImport.detect(text))
        assertFalse(BitwardenImport.detect(text))
        checkCases(OnePasswordImport.parse(text), "1password-cases.json")
    }

    @Test fun unzip() {
        val zip = ByteArrayOutputStream().also { out ->
            ZipOutputStream(out).use { z ->
                z.putNextEntry(ZipEntry("export.attributes")); z.write("{}".toByteArray())
                z.putNextEntry(ZipEntry("files/big.bin")); z.write(ByteArray(1 shl 20))
                z.putNextEntry(ZipEntry("export.data")); z.write(text.toByteArray())
            }
        }.toByteArray()
        assertEquals(text, OnePasswordImport.unzip(zip.inputStream(), 20 shl 20))
        val other = ByteArrayOutputStream().also { out -> ZipOutputStream(out).use { z -> z.putNextEntry(ZipEntry("a.txt")) } }.toByteArray()
        assertNull(OnePasswordImport.unzip(other.inputStream(), 20 shl 20))
        assertFalse(OnePasswordImport.detect("""{"encrypted": false, "items": []}"""))
    }
}
