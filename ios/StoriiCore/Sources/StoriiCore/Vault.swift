import Foundation

/// What is kept on disk: the session token and the still-encrypted vault. Useless without the master password.
public struct VaultState: Codable, Equatable, Sendable {
    public var server: String
    public var username: String
    public var token: String
    public var kdf: KDF
    public var wrappedKey: String
    public var revision: Int64 = 0
    public var items: [String: RemoteItem] = [:]
    public var expired = false

    enum CodingKeys: String, CodingKey {
        case server, username, token, kdf, revision, items, expired
        case wrappedKey = "wrapped_key"
    }

    public init(server: String, username: String, token: String, kdf: KDF, wrappedKey: String) {
        self.server = server
        self.username = username
        self.token = token
        self.kdf = kdf
        self.wrappedKey = wrappedKey
    }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        server = try c.decode(String.self, forKey: .server)
        username = try c.decode(String.self, forKey: .username)
        token = try c.decode(String.self, forKey: .token)
        kdf = try c.decode(KDF.self, forKey: .kdf)
        wrappedKey = try c.decode(String.self, forKey: .wrappedKey)
        revision = try c.decodeIfPresent(Int64.self, forKey: .revision) ?? 0
        items = try c.decodeIfPresent([String: RemoteItem].self, forKey: .items) ?? [:]
        expired = try c.decodeIfPresent(Bool.self, forKey: .expired) ?? false
    }
}

public enum VaultStatus: Equatable, Sendable {
    case notSetUp
    case locked(username: String, server: String, expired: Bool)
    case unlocked(username: String, server: String)
}

public enum Change: Sendable {
    case put(id: String?, item: Item)
    case delete(id: String)
}

/// The vault: the encrypted state on disk and, while unlocked, the vault key and decrypted items in memory. The app and
/// the AutoFill extension each have one, over the same file in the shared app group container.
@MainActor
public final class Vault {
    public let file: URL
    public private(set) var state: VaultState?
    private var vaultKey: Data?
    public private(set) var items: [String: Item] = [:]
    /// Called after every change of status or items.
    public var onChange: (@MainActor () -> Void)?

    public init(file: URL) {
        self.file = file
        state = Self.load(file)
    }

    public var isSetUp: Bool { state != nil }
    public var isUnlocked: Bool { vaultKey != nil }
    /// The vault key while unlocked, e.g. to store it for Face ID.
    public var key: Data? { vaultKey }

    public var status: VaultStatus {
        guard let s = state else { return .notSetUp }
        if vaultKey == nil || s.expired { return .locked(username: s.username, server: s.server, expired: s.expired) }
        return .unlocked(username: s.username, server: s.server)
    }

    private static func load(_ file: URL) -> VaultState? {
        guard let data = try? Data(contentsOf: file) else { return nil }
        return try? JSONDecoder().decode(VaultState.self, from: data)
    }

    /// Re-reads the file, which the other process (app or extension) may have changed.
    public func reload() {
        state = Self.load(file)
        if state == nil { lock() } else { decryptAll(); onChange?() }
    }

    private func save(_ s: VaultState) throws {
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        #if os(iOS)
        try JSONEncoder().encode(s).write(to: file, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        #else
        try JSONEncoder().encode(s).write(to: file, options: [.atomic])
        #endif
        state = s
    }

    private func decryptAll() {
        guard let key = vaultKey, let s = state else {
            items = [:]
            return
        }
        var out: [String: Item] = [:]
        for (id, r) in s.items {
            if let d = r.data, let it = try? StoriiCrypto.decryptItem(vaultKey: key, id: id, data: d) { out[id] = it }
        }
        items = out
    }

    nonisolated private static func derive(_ password: String, _ kdf: KDF) async throws -> StoriiCrypto.Keys {
        try await Task.detached(priority: .userInitiated) { try StoriiCrypto.deriveKeys(password: password, kdf: kdf) }.value
    }

    /// Logs in (or registers) and unlocks. Replaces whatever account was on this device.
    public func login(server: String, username: String, password: String, register: Bool, device: String) async throws {
        var api = API(API.normalize(server))
        try await api.ping()
        let key: Data
        let resp: SessionResponse
        if register {
            let kdf = KDF.new()
            let keys = try await Self.derive(password, kdf)
            key = StoriiCrypto.randomBytes(32)
            resp = try await api.register(username: username, kdf: kdf, authKey: keys.authKey,
                                          wrappedKey: StoriiCrypto.wrapVaultKey(wrap: keys.wrap, vaultKey: key), device: device)
        } else {
            let keys = try await Self.derive(password, api.prelogin(username: username))
            resp = try await api.login(username: username, authKey: keys.authKey, device: device)
            key = try StoriiCrypto.unwrapVaultKey(wrap: keys.wrap, wrapped: resp.account.wrappedKey)
        }
        api.token = resp.token
        let s = VaultState(server: api.baseURL, username: resp.account.username, token: resp.token, kdf: resp.account.kdf,
                           wrappedKey: resp.account.wrappedKey)
        try save(await Self.pull(s))
        vaultKey = key
        decryptAll()
        onChange?()
    }

    /// Unlocks with the master password. Works offline. Returns the vault key, for Face ID enrolment.
    @discardableResult
    public func unlock(password: String) async throws -> Data {
        guard let s = state else { throw StoriiError("Not set up") }
        let keys = try await Self.derive(password, s.kdf)
        guard let key = try? StoriiCrypto.unwrapVaultKey(wrap: keys.wrap, wrapped: s.wrappedKey) else {
            throw StoriiError("Wrong master password")
        }
        try unlock(key: key)
        return key
    }

    /// Unlocks with a vault key kept for Face ID. It must still open this account's vault.
    public func unlock(key: Data) throws {
        guard let s = state else { throw StoriiError("Not set up") }
        if let (id, r) = s.items.first, let d = r.data { _ = try StoriiCrypto.decryptItem(vaultKey: key, id: id, data: d) }
        vaultKey = key
        decryptAll()
        onChange?()
    }

    public func lock() {
        vaultKey = nil
        items = [:]
        onChange?()
    }

    public func logout() async {
        if let s = state { try? await API(s.server, token: s.token).logout() }
        try? FileManager.default.removeItem(at: file)
        state = nil
        lock()
    }

    private static func pull(_ s: VaultState) async throws -> VaultState {
        let api = API(s.server, token: s.token)
        let acct = try await api.account()
        let sync = try await api.sync(since: s.revision)
        var out = s
        // since=0 is a full snapshot without tombstones: replace, or deletions made elsewhere would never arrive.
        if s.revision == 0 { out.items = [:] }
        for it in sync.items {
            if it.deleted { out.items[it.id] = nil } else { out.items[it.id] = it }
        }
        out.kdf = acct.kdf
        out.wrappedKey = acct.wrappedKey
        out.revision = sync.revision
        return out
    }

    /// Fetches changes; marks the session expired when the server no longer accepts it.
    public func sync() async throws {
        guard let s = state else { return }
        do {
            try save(await Self.pull(s))
        } catch let e as APIError where e.unauthorized {
            var x = s
            x.expired = true
            try? save(x)
            lock()
            throw e
        }
        decryptAll()
        onChange?()
    }

    /// Uploads changes and applies them locally. Returns the ids, new ones included.
    @discardableResult
    public func write(_ changes: [Change]) async throws -> [String] {
        guard var s = state else { throw StoriiError("Not set up") }
        guard let key = vaultKey else { throw StoriiError("Locked") }
        let now = Item.now()
        var writes: [Write] = []
        for ch in changes {
            switch ch {
            case .delete(let id):
                writes.append(Write(id: id, delete: true))
            case .put(let id, var item):
                try item.validate()
                let id = id ?? UUID().uuidString.lowercased()
                if item.createdAt == nil { item.createdAt = now }
                item.updatedAt = now
                writes.append(Write(id: id, data: try StoriiCrypto.encryptItem(vaultKey: key, id: id, item: item)))
            }
        }
        let rev = try await API(s.server, token: s.token).write(writes)
        // Another write may have landed while this one was in flight; start from the newest state.
        s = state ?? s
        for w in writes {
            if w.delete { s.items[w.id] = nil } else { s.items[w.id] = RemoteItem(id: w.id, data: w.data, revision: rev) }
        }
        try save(s)
        decryptAll()
        onChange?()
        return writes.map(\.id)
    }

    @discardableResult
    public func put(_ id: String?, _ item: Item) async throws -> String { try await write([.put(id: id, item: item)])[0] }

    /// Deletes items; deleting a context also unlinks it from its secrets.
    public func delete(_ ids: [String]) async throws {
        let gone = Set(ids)
        var changes: [Change] = items.filter { !gone.contains($0.key) && $0.value.contexts.contains(where: gone.contains) }
            .map { id, s in
                var x = s
                x.contexts.removeAll(where: gone.contains)
                return .put(id: id, item: x)
            }
        changes += ids.map { .delete(id: $0) }
        try await write(changes)
    }

    private func sorted(_ f: (Item) -> Bool) -> [Entry] {
        items.filter { f($0.value) }.map { Entry(id: $0.key, item: $0.value) }
            .sorted { $0.item.name.localizedCaseInsensitiveCompare($1.item.name) == .orderedAscending }
    }

    public func secrets() -> [Entry] { sorted(\.isSecret) }
    public func contexts() -> [Entry] { sorted(\.isContext) }
    public func get(_ id: String) -> Item? { items[id] }

    /// Secrets whose contexts match a web host (an app's associated domain on iOS).
    public func forHost(_ host: String) -> [Entry] {
        let ctxIDs = Set(items.filter { $0.value.matches(host: host) }.keys)
        return secrets().filter { $0.item.contexts.contains(where: ctxIDs.contains) }
    }

    /// Search over names, usernames, issuers and context names.
    public func search(_ query: String, types: [String]? = nil) -> [Entry] {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        return secrets().filter { e in
            if let types, !types.contains(e.item.type ?? "") { return false }
            if q.isEmpty { return true }
            let hay = [e.item.name, e.item.field("username"), e.item.field("issuer"), e.item.field("account")]
                + e.item.contexts.compactMap { items[$0]?.name } + e.item.contexts.flatMap { items[$0]?.urls ?? [] }
            return hay.contains { $0.lowercased().contains(q) }
        }
    }

    /// Links a secret to the website it was just used for, creating a context if needed, so it is offered directly next time.
    public func remember(secretID: String, host: String) async throws {
        guard var secret = items[secretID], !Match.host(host).isEmpty else { return }
        let h = Match.host(host)
        var changes: [Change] = []
        let ctxID: String
        // A context that already covers the host (e.g. google.com for accounts.google.com) is reused.
        if let existing = contexts().first(where: { $0.item.matches(host: h) }) {
            ctxID = existing.id
        } else {
            ctxID = UUID().uuidString.lowercased()
            changes.append(.put(id: ctxID, item: .context(h, urls: ["https://" + h])))
        }
        if !secret.contexts.contains(ctxID) {
            secret.contexts.append(ctxID)
            changes.append(.put(id: secretID, item: secret))
        }
        if !changes.isEmpty { try await write(changes) }
    }

    /// Password logins and 2FA codes by the hosts they are offered for: what the system AutoFill list is built from.
    public func identities() -> [(entry: Entry, hosts: [String])] {
        secrets().filter { $0.item.type == Item.password || $0.item.type == Item.totp }.map { e in
            let hosts = e.item.contexts.compactMap { items[$0] }.flatMap(\.urls).map { Match.host($0) }.filter { !$0.isEmpty }
            return (e, Array(Set(hosts)).sorted())
        }
    }
}
