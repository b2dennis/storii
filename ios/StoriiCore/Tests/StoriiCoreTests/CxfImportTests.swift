import Foundation
import Testing
@testable import StoriiCore

private let testdata = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("../../../../testdata").standardized

private func json(_ path: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(contentsOf: testdata.appendingPathComponent(path))) as! [String: Any]
}

private func item(_ o: Any) throws -> Item { try Item.decode(JSONSerialization.data(withJSONObject: o)) }

/// Imports `parsed` into the vault of testdata/import/`casesFile` and compares the plan with its lines, as the Kotlin
/// tests' checkCases.
private func checkCases(_ parsed: Import.Parsed, _ casesFile: String) throws {
    let cases = try json("import/" + casesFile)
    let privateKey = (try json("passkey.json")["passkey"] as! [String: Any])["private_key"] as! String
    #expect(cases["failed"] as! [String] == parsed.failed.map { String($0.prefix { $0 != "(" }).trimmingCharacters(in: .whitespaces) })
    let existing = try (cases["existing"] as! [String: Any]).mapValues(item)
    var n = 0
    let plan = Import.build(existing: existing, parsed, newId: { n += 1; return "new-\(n)" })
    let want = cases["lines"] as! [[String: Any]]
    try #require(want.count == plan.lines.count)
    for (i, w) in want.enumerated() {
        let got = plan.lines[i]
        let line = Comment(rawValue: "line \(i + 1)")
        #expect([w["action"] as! String, w["id"] as! String, w["name"] as! String] == [got.action.rawValue, got.id ?? "", got.name], line)
        guard w["action"] as! String == "add" else { continue }
        let it = try #require(plan[got.id!])
        var fields = it.fields
        if it.type == Item.passkey {
            #expect(fields["private_key"] == privateKey, line)
            fields["private_key"] = nil
        }
        #expect(it.type == w["type"] as? String, line)
        #expect(it.notes ?? "" == w["notes"] as? String ?? "", line)
        #expect(it.contexts == w["contexts"] as? [String] ?? [], line)
        #expect(fields == w["fields"] as! [String: String], line)
    }
    let newContexts = cases["new_contexts"] as! [String: Any]
    for (id, e) in newContexts {
        let w = try item(e), c = try #require(plan[id])
        #expect(c.name == w.name && c.contextType == w.contextType && c.urls == w.urls, Comment(rawValue: id))
    }
    #expect(plan.writes.count == want.filter { $0["action"] as! String == "add" }.count + newContexts.count)
    // Importing the same file again changes nothing.
    var after = existing
    for (id, it) in plan.writes { after[id] = it }
    #expect(Import.build(existing: after, parsed, newId: { "x" }).writes.isEmpty)
}

@Suite struct CxfImportTests {
    @Test func sharedCases() throws {
        try checkCases(CxfImport.parse(Data(contentsOf: testdata.appendingPathComponent("import/cxf.json"))), "cxf-cases.json")
    }

    @Test func notCxf() throws {
        #expect(throws: Import.NotAnExport.self) { try CxfImport.parse(Data(#"{"items": []}"#.utf8)) }
        #expect(try CxfImport.parse(Data(#"{"version":{"major":1,"minor":0},"accounts":[]}"#.utf8)).count == 0)
    }

    @Test func envelope() throws {
        let doc = try String(contentsOf: testdata.appendingPathComponent("import/cxf.json"), encoding: .utf8)
        let want = try CxfImport.parse(Data(doc.utf8))
        let b64 = Passkey.b64u(Data(doc.utf8))
        for wrapped in [#"{"version":0,"payload":\#(doc)}"#, #"{"payload":"\#(b64)"}"#] {
            #expect(try CxfImport.parse(Data(wrapped.utf8)) == want)
        }
    }

    @Test func guidCredentialId() throws {
        let key = (try json("passkey.json")["passkey"] as! [String: Any])["private_key"] as! String
        let f = try Import.passkey(credentialId: "c3a7e6a2-1f0d-4c5e-9a7b-0123456789ab", key: key, userHandle: "")
        #expect(f["credential_id"] == Passkey.b64u(Data([0xc3, 0xa7, 0xe6, 0xa2, 0x1f, 0x0d, 0x4c, 0x5e, 0x9a, 0x7b, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab])))
        #expect(throws: StoriiError.self) { try Import.passkey(credentialId: "YQ", key: "AAAA", userHandle: "") }
    }
}
