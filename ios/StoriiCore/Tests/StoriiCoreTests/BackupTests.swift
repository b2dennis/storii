import Foundation
import XCTest
@testable import StoriiCore

/// testdata/backup.json, shared with internal/vault/backup_test.go.
final class BackupTests: XCTestCase {
    struct Vector: Decodable {
        let password: String
        let items: [String: Item]
    }
    let raw = try! Data(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../../../testdata/backup.json").standardized)

    func vector() throws -> (Vector, Data) {
        let v = try JSONDecoder().decode(Vector.self, from: raw)
        let o = try JSONSerialization.jsonObject(with: raw) as! [String: Any]
        return (v, try JSONSerialization.data(withJSONObject: o["file"]!))
    }

    func testOpensTheSharedBackup() throws {
        let (v, file) = try vector()
        XCTAssertTrue(Backup.isBackup(file))
        XCTAssertFalse(Backup.isBackup(Data(#"{"items":[]}"#.utf8)))
        XCTAssertFalse(Backup.isBackup(Data("url,username".utf8)))
        let items = try Backup.open(password: v.password, file: file)
        XCTAssertEqual(try items.mapValues { try Item.decode($0) }, v.items)
        XCTAssertThrowsError(try Backup.open(password: "wrong", file: file)) { XCTAssertTrue($0 is Backup.WrongPassword) }
    }

    func testRoundTripAndPlan() throws {
        let (v, file) = try vector()
        let items = try Backup.open(password: v.password, file: file)
        let again = try Backup.seal(password: "other pw", items: items,
                                    kdf: KDF(salt: StoriiCrypto.randomBytes(16).base64EncodedString(), iterations: 1, memoryKib: 16384, parallelism: 1))
        XCTAssertEqual(try Backup.open(password: "other pw", file: again).mapValues { try Item.decode($0) }, v.items)
        let ids = items.keys.sorted()
        var extra = items
        extra["nope"] = Data("{}".utf8)
        let plan = Backup.plan(extra, have: [ids[0]])
        XCTAssertEqual(Set(plan.add.map(\.id)), Set(ids.dropFirst()))
        XCTAssertEqual(plan.skipped, 2)
    }
}
