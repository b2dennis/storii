package sh.base2.storii

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import sh.base2.storii.core.CxfImport
import sh.base2.storii.core.Import
import java.io.File
import java.util.Base64

/** testdata/import/cxf*.json: what Android's credential transfer hands over. */
class CxfImportTest {
    @Test fun sharedCases() = checkCases(CxfImport.parse(File("../../testdata/import/cxf.json").readText()), "cxf-cases.json")

    @Test fun notCxf() {
        assertThrows(Import.NotAnExport::class.java) { CxfImport.parse("{\"items\": []}") }
        assertEquals(0, CxfImport.parse("""{"version":{"major":1,"minor":0},"accounts":[]}""").count)
    }

    @Test fun envelope() {
        val doc = File("../../testdata/import/cxf.json").readText()
        val want = CxfImport.parse(doc)
        val b64 = Base64.getUrlEncoder().withoutPadding().encodeToString(doc.toByteArray())
        for (wrapped in listOf("{\"version\":0,\"payload\":$doc}", "{\"payload\":\"$b64\"}")) assertEquals(want, CxfImport.parse(wrapped))
    }
}
