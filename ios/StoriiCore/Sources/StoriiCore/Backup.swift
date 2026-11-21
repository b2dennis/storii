import Foundation

/// Encrypted storii backups (internal/vault/backup.go has the format): every item's plaintext keyed by id, sealed with
/// a key derived from a backup password like the login keys (Argon2id + HKDF "storii wrap"), with AAD "storii:backup".
public enum Backup {
    public static let version = 1
    static let aad = "storii:backup"

    public struct WrongPassword: LocalizedError {
        public var errorDescription: String? { "Wrong backup password, or the file is damaged." }
    }
    public struct NotABackup: LocalizedError {
        public var message = "That isn't a storii backup."
        public var errorDescription: String? { message }
    }

    struct File: Codable {
        var version: Int
        var exportedAt: String
        var kdf: KDF
        var data: String
        enum CodingKeys: String, CodingKey {
            case version = "storii_backup", exportedAt = "exported_at", kdf, data
        }
    }

    public static func isBackup(_ data: Data) -> Bool {
        guard let o = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let v = o["storii_backup"] as? Int else { return false }
        return v > 0
    }

    /// `items`: id → the item's JSON. Returns the file.
    public static func seal(password: String, items: [String: Data], kdf: KDF = .new(), now: Date = Date(),
                            nonce: Data? = nil) throws -> Data {
        let keys = try StoriiCrypto.deriveKeys(password: password, kdf: kdf)
        var objects: [String: Any] = [:]
        for (id, raw) in items { objects[id] = try JSONSerialization.jsonObject(with: raw) }
        let plain = try JSONSerialization.data(withJSONObject: ["items": objects], options: [.sortedKeys])
        let f = File(version: version, exportedAt: ISO8601DateFormatter().string(from: now), kdf: kdf,
                     data: try StoriiCrypto.seal(key: keys.wrap, plaintext: plain, aad: aad, nonce: nonce))
        let enc = JSONEncoder()
        enc.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return try enc.encode(f)
    }

    /// Returns id → the item's JSON.
    public static func open(password: String, file: Data) throws -> [String: Data] {
        guard isBackup(file) else { throw NotABackup() }
        guard let f = try? JSONDecoder().decode(File.self, from: file) else { throw NotABackup(message: "That backup is damaged.") }
        guard f.version == version else { throw NotABackup(message: "This backup (version \(f.version)) needs a newer storii.") }
        let keys = try StoriiCrypto.deriveKeys(password: password, kdf: f.kdf)
        let plain: Data
        do { plain = try StoriiCrypto.open(key: keys.wrap, data: f.data, aad: aad) } catch { throw WrongPassword() }
        guard let o = try JSONSerialization.jsonObject(with: plain) as? [String: Any],
              let items = o["items"] as? [String: Any] else { throw NotABackup(message: "That backup is damaged.") }
        var out: [String: Data] = [:]
        for (id, v) in items { out[id] = try JSONSerialization.data(withJSONObject: v, options: [.fragmentsAllowed]) }
        return out
    }

    public struct Entry: Sendable {
        public let id: String
        public let item: Item
        public let raw: Data
    }

    /// What restoring adds: the backup's valid items the vault doesn't have, sorted by name.
    public struct Plan: Sendable {
        public let add: [Entry]
        public let skipped: Int
    }

    public static func plan(_ items: [String: Data], have: Set<String>) -> Plan {
        var skipped = 0
        var add: [Entry] = []
        for (id, raw) in items {
            guard UUID(uuidString: id) != nil, id.count == 36, !have.contains(id),
                  let item = try? Item.decode(raw), !item.name.trimmingCharacters(in: .whitespaces).isEmpty,
                  item.isSecret || item.isContext else { skipped += 1; continue }
            add.append(Entry(id: id, item: item, raw: raw))
        }
        return Plan(add: add.sorted { $0.item.name.lowercased() < $1.item.name.lowercased() }, skipped: skipped)
    }
}
