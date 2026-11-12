import Foundation
import XCTest
@testable import StoriiCore

/// testdata/cards.json, shared with the Go, JS and Kotlin tests.
final class CardTests: XCTestCase {
    struct Cases: Decodable {
        struct Number: Decodable { let number, brand, masked: String; let valid: Bool }
        struct Expiry: Decodable { let input, normalized: String }
        let numbers: [Number]
        let expiry: [Expiry]
    }

    func testCards() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../testdata/cards.json").standardized
        let c = try JSONDecoder().decode(Cases.self, from: Data(contentsOf: url))
        for n in c.numbers {
            XCTAssertEqual(Card.brand(n.number), n.brand, n.number)
            XCTAssertEqual(Card.valid(n.number), n.valid, n.number)
            XCTAssertEqual(Card.masked(n.number), n.masked, n.number)
        }
        for e in c.expiry { XCTAssertEqual(Card.normalizeExpiry(e.input), e.normalized, e.input) }
    }
}
