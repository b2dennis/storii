import Foundation

/// A value a secret had before it was changed.
public struct HistoryEntry: Codable, Equatable, Hashable, Sendable {
    public var field: String
    public var value: String
    public var changedAt: String

    public init(field: String, value: String, changedAt: String) {
        self.field = field
        self.value = value
        self.changedAt = changedAt
    }

    enum CodingKeys: String, CodingKey { case field, value, changedAt = "changed_at" }
}

/// Password history, as internal/vault/history.go (shared cases: testdata/history.json).
public enum PasswordHistory {
    public static let max = 10
    public static let fields = ["password", "key"]

    /// next as it should be stored when it replaces prev: the history always comes from prev, and each history field
    /// whose value changed adds prev's value in front. now is an RFC 3339 time in whole seconds.
    public static func apply(prev: Item, next: Item, now: String) -> Item {
        var h = prev.history
        if prev.isSecret {
            for f in fields.reversed() {
                if let old = prev.fields[f], !old.isEmpty, old != next.fields[f] {
                    h.insert(HistoryEntry(field: f, value: old, changedAt: now), at: 0)
                }
            }
        }
        var out = next
        out.history = Array(h.prefix(max))
        return out
    }
}
