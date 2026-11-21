import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// Password health, as internal/vault/health.go (shared cases: testdata/health.json).
public enum PasswordHealth {
    public static let weakBits = 50.0
    public static let pwnedRangeURL = "https://api.pwnedpasswords.com/range/"

    public struct Report: Equatable, Sendable {
        public var weak: [String]
        public var reused: [[String]]
    }

    /// Too short or too guessable: under 8 characters, under 5 different ones, or under weakBits by
    /// length × log2(pool), where the pool counts 26 lowercase, 26 uppercase, 10 digits and 33 for anything else.
    public static func isWeak(_ pw: String) -> Bool {
        let r = Array(pw.unicodeScalars)
        if r.count < 8 || Set(r).count < 5 { return true }
        var lower = false, upper = false, digit = false, other = false
        for c in r {
            switch c {
            case "a"..."z": lower = true
            case "A"..."Z": upper = true
            case "0"..."9": digit = true
            default: other = true
            }
        }
        let pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (other ? 33 : 0)
        return Double(r.count) * log2(Double(pool)) < weakBits
    }

    /// Password items with a password, as id → password.
    public static func passwords(_ items: [String: Item]) -> [String: String] {
        items.compactMapValues { it in
            it.isSecret && it.type == Item.password && !it.field("password").isEmpty ? it.field("password") : nil
        }
    }

    /// Weak ids, and groups of ids sharing a password (each sorted, groups by their first id).
    public static func check(_ items: [String: Item]) -> Report {
        let pws = passwords(items)
        let reused = Dictionary(grouping: pws.keys, by: { pws[$0]! }).values
            .filter { $0.count > 1 }.map { $0.sorted() }.sorted { $0[0] < $1[0] }
        return Report(weak: pws.filter { isWeak($0.value) }.keys.sorted(), reused: reused)
    }

    /// The uppercase SHA-1 split into the 5 characters sent to Have I Been Pwned and the rest.
    public static func pwnedHash(_ pw: String) -> (prefix: String, suffix: String) {
        let h = Insecure.SHA1.hash(data: Data(pw.utf8)).map { String(format: "%02X", $0) }.joined()
        return (String(h.prefix(5)), String(h.dropFirst(5)))
    }

    /// How often suffix appears in a range answer ("SUFFIX:COUNT" lines; padding lines have count 0).
    public static func pwnedCount(_ body: String, suffix: String) -> Int {
        for line in body.split(whereSeparator: \.isNewline) {
            let parts = line.trimmingCharacters(in: .whitespaces).split(separator: ":")
            if parts.count == 2, parts[0].uppercased() == suffix.uppercased() { return Int(parts[1]) ?? 0 }
        }
        return 0
    }

    /// Asks Have I Been Pwned how often each password was seen in breaches; only the first 5 hex digits of each SHA-1
    /// leave the device, and answers are padded. Returns password → count for the ones that were seen.
    public static func pwned(_ passwords: some Collection<String>) async throws -> [String: Int] {
        var found: [String: Int] = [:]
        for pw in Set(passwords) {
            let (prefix, suffix) = pwnedHash(pw)
            var req = URLRequest(url: URL(string: pwnedRangeURL + prefix)!, timeoutInterval: 20)
            req.setValue("true", forHTTPHeaderField: "Add-Padding")
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard (resp as? HTTPURLResponse)?.statusCode == 200 else { throw StoriiError("The breach check failed.") }
            let n = pwnedCount(String(decoding: data, as: UTF8.self), suffix: suffix)
            if n > 0 { found[pw] = n }
        }
        return found
    }
}
