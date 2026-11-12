import Foundation

public struct CustomField: Codable, Equatable, Hashable, Sendable {
    public var name: String
    public var value: String
    public var hidden: Bool

    public init(name: String, value: String, hidden: Bool = false) {
        self.name = name
        self.value = value
        self.hidden = hidden
    }

    enum CodingKeys: String, CodingKey { case name, value, hidden }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        value = try c.decodeIfPresent(String.self, forKey: .value) ?? ""
        hidden = try c.decodeIfPresent(Bool.self, forKey: .hidden) ?? false
    }

    public func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .name)
        try c.encode(value, forKey: .value)
        if hidden { try c.encode(true, forKey: .hidden) }
    }
}

/// The decrypted JSON of one item: a secret or a context (internal/vault/item.go). Empty values are left out, like Go's
/// omitempty, so every client writes the same shape.
public struct Item: Codable, Equatable, Hashable, Sendable {
    public static let kindSecret = "secret", kindContext = "context"
    public static let password = "password", totp = "totp", apiKey = "api_key", note = "note", card = "card"
    /// Created by the browser extension; listed, not edited.
    public static let passkey = "passkey"
    public static let types = [password, totp, apiKey, note, card]
    public static let contextTypes = ["website", "app", "other"]

    public var kind: String
    public var name: String
    public var type: String?
    public var contexts: [String]
    public var fields: [String: String]
    public var custom: [CustomField]
    public var contextType: String?
    public var urls: [String]
    public var androidPackages: [String]
    public var notes: String?
    public var createdAt: String?
    public var updatedAt: String?

    public init(kind: String, name: String, type: String? = nil, contexts: [String] = [], fields: [String: String] = [:],
                custom: [CustomField] = [], contextType: String? = nil, urls: [String] = [], androidPackages: [String] = [],
                notes: String? = nil, createdAt: String? = nil, updatedAt: String? = nil) {
        self.kind = kind
        self.name = name
        self.type = type
        self.contexts = contexts
        self.fields = fields
        self.custom = custom
        self.contextType = contextType
        self.urls = urls
        self.androidPackages = androidPackages
        self.notes = notes
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public static func secret(_ type: String, name: String, fields: [String: String] = [:]) -> Item {
        Item(kind: kindSecret, name: name, type: type, fields: fields)
    }

    public static func context(_ name: String, type: String = "website", urls: [String] = []) -> Item {
        Item(kind: kindContext, name: name, contextType: type, urls: urls)
    }

    public var isSecret: Bool { kind == Item.kindSecret }
    public var isContext: Bool { kind == Item.kindContext }
    public func field(_ name: String) -> String { fields[name] ?? "" }

    /// Does this context apply to a web host?
    public func matches(host: String) -> Bool {
        isContext && !host.isEmpty && urls.contains { Match.matchesHost(contextURL: $0, pageHost: host) }
    }

    /// What "copy" means for each type: the password, the current code, the key or the note.
    public func secretValue(now: Date = Date()) throws -> String {
        switch type {
        case Item.password: return field("password")
        case Item.totp: return try TOTP(fields: fields).code(at: now)
        case Item.apiKey: return field("key")
        case Item.card: return Card.digits(field("number"))
        default: return notes ?? ""
        }
    }

    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespaces).isEmpty else { throw StoriiError("Give it a name.") }
        switch kind {
        case Item.kindSecret:
            guard let type, (Item.types + [Item.passkey]).contains(type) else { throw StoriiError("Unknown secret type \(type ?? "")") }
            if type == Item.totp { _ = try TOTP(fields: fields) }
        case Item.kindContext:
            guard let contextType, Item.contextTypes.contains(contextType) else {
                throw StoriiError("Unknown context type \(contextType ?? "")")
            }
        default: throw StoriiError("Unknown item kind \(kind)")
        }
    }

    enum CodingKeys: String, CodingKey {
        case kind, name, type, contexts, fields, custom, urls, notes
        case contextType = "context_type", androidPackages = "android_packages"
        case createdAt = "created_at", updatedAt = "updated_at"
    }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        kind = try c.decodeIfPresent(String.self, forKey: .kind) ?? ""
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        type = try c.decodeIfPresent(String.self, forKey: .type)
        contexts = try c.decodeIfPresent([String].self, forKey: .contexts) ?? []
        fields = try c.decodeIfPresent([String: String].self, forKey: .fields) ?? [:]
        custom = try c.decodeIfPresent([CustomField].self, forKey: .custom) ?? []
        contextType = try c.decodeIfPresent(String.self, forKey: .contextType)
        urls = try c.decodeIfPresent([String].self, forKey: .urls) ?? []
        androidPackages = try c.decodeIfPresent([String].self, forKey: .androidPackages) ?? []
        notes = try c.decodeIfPresent(String.self, forKey: .notes)
        createdAt = try c.decodeIfPresent(String.self, forKey: .createdAt)
        updatedAt = try c.decodeIfPresent(String.self, forKey: .updatedAt)
    }

    public func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(kind, forKey: .kind)
        try c.encode(name, forKey: .name)
        func opt(_ s: String?, _ k: CodingKeys) throws { if let s, !s.isEmpty { try c.encode(s, forKey: k) } }
        try opt(type, .type)
        if !contexts.isEmpty { try c.encode(contexts, forKey: .contexts) }
        if !fields.isEmpty { try c.encode(fields, forKey: .fields) }
        if !custom.isEmpty { try c.encode(custom, forKey: .custom) }
        try opt(contextType, .contextType)
        if !urls.isEmpty { try c.encode(urls, forKey: .urls) }
        if !androidPackages.isEmpty { try c.encode(androidPackages, forKey: .androidPackages) }
        try opt(notes, .notes)
        try opt(createdAt, .createdAt)
        try opt(updatedAt, .updatedAt)
    }

    public func json() throws -> Data {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try enc.encode(self)
    }

    public static func decode(_ data: Data) throws -> Item { try JSONDecoder().decode(Item.self, from: data) }

    /// RFC 3339 in UTC, whole seconds, as Go writes it.
    public static func now(_ date: Date = Date()) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime]
        return f.string(from: date)
    }
}

/// An item with its id.
public struct Entry: Identifiable, Equatable, Hashable, Sendable {
    public let id: String
    public let item: Item
    public init(id: String, item: Item) {
        self.id = id
        self.item = item
    }
}

public func typeLabel(_ type: String?) -> String {
    switch type {
    case Item.password: "Password"
    case Item.totp: "2FA code"
    case Item.apiKey: "API key"
    case Item.note: "Note"
    case Item.card: "Card"
    case Item.passkey: "Passkey"
    default: type ?? "?"
    }
}
