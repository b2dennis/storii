import Foundation
import XCTest
@testable import StoriiCore

/// testdata/history.json, shared with the Go, JS and Kotlin tests.
final class PasswordHistoryTests: XCTestCase {
    struct Cases: Decodable {
        struct Case: Decodable { let name: String; let prev, next: Item; let want: [HistoryEntry]? }
        let now: String
        let cases: [Case]
    }

    func testCases() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../testdata/history.json").standardized
        let c = try JSONDecoder().decode(Cases.self, from: Data(contentsOf: url))
        for t in c.cases {
            XCTAssertEqual(PasswordHistory.apply(prev: t.prev, next: t.next, now: c.now).history, t.want ?? [], t.name)
        }
    }
}
