import Foundation
import XCTest
@testable import StoriiCore

/// testdata/health.json, shared with the Go, JS and Kotlin tests.
final class PasswordHealthTests: XCTestCase {
    struct Cases: Decodable {
        struct Weak: Decodable { let password: String; let weak: Bool }
        struct Health: Decodable { let weak: [String]; let reused: [[String]] }
        struct Pwned: Decodable {
            let password, prefix, suffix, body, missing_suffix, padding_suffix: String
            let count: Int
        }
        let weak: [Weak]
        let items: [String: Item]
        let health: Health
        let pwned: Pwned
    }

    func testHealth() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../testdata/health.json").standardized
        let c = try JSONDecoder().decode(Cases.self, from: Data(contentsOf: url))
        for w in c.weak { XCTAssertEqual(PasswordHealth.isWeak(w.password), w.weak, w.password) }
        XCTAssertEqual(PasswordHealth.check(c.items), PasswordHealth.Report(weak: c.health.weak, reused: c.health.reused))
        let p = c.pwned
        let h = PasswordHealth.pwnedHash(p.password)
        XCTAssertEqual([h.prefix, h.suffix], [p.prefix, p.suffix])
        XCTAssertEqual(PasswordHealth.pwnedCount(p.body, suffix: p.suffix), p.count)
        XCTAssertEqual(PasswordHealth.pwnedCount(p.body, suffix: p.missing_suffix), 0)
        XCTAssertEqual(PasswordHealth.pwnedCount(p.body, suffix: p.padding_suffix), 0)
    }
}
