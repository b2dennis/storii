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
    public var publicKey = ""
    public var sealedPrivateKey = ""
    public var shares: [String: ShareState] = [:]

    enum CodingKeys: String, CodingKey {
        case server, username, token, kdf, revision, items, expired, shares
        case wrappedKey = "wrapped_key", publicKey = "public_key", sealedPrivateKey = "sealed_private_key"
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
        publicKey = try c.decodeIfPresent(String.self, forKey: .publicKey) ?? ""
        sealedPrivateKey = try c.decodeIfPresent(String.self, forKey: .sealedPrivateKey) ?? ""
        shares = try c.decodeIfPresent([String: ShareState].self, forKey: .shares) ?? [:]
    }
}

/// A share as kept on disk, still encrypted.
public struct ShareState: Codable, Equatable, Sendable {
    public var owner: String
    public var meta: String
    public var wrappedKey: String
    public var members: [ShareMember] = []
    public var revision: Int64 = 0
    public var items: [String: RemoteItem] = [:]

    enum CodingKeys: String, CodingKey {
        case owner, meta, members, revision, items
        case wrappedKey = "wrapped_key"
    }

    public init(owner: String, meta: String, wrappedKey: String, members: [ShareMember] = []) {
        self.owner = owner
        self.meta = meta
        self.wrappedKey = wrappedKey
        self.members = members
    }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        owner = try c.decode(String.self, forKey: .owner)
        meta = try c.decode(String.self, forKey: .meta)
        wrappedKey = try c.decode(String.self, forKey: .wrappedKey)
        members = try c.decodeIfPresent([ShareMember].self, forKey: .members) ?? []
        revision = try c.decodeIfPresent(Int64.self, forKey: .revision) ?? 0
        items = try c.decodeIfPresent([String: RemoteItem].self, forKey: .items) ?? [:]
    }
}

/// A share this account can open.
public struct Share: Identifiable, Equatable, Sendable {
    public let id: String
    public let name: String
    public let owner: String
    public let members: [ShareMember]
    /// This account owns it (and may rename, delete and add or remove people).
    public let mine: Bool
}

public enum VaultStatus: Equatable, Sendable {
    case notSetUp
    case locked(username: String, server: String, expired: Bool)
    case unlocked(username: String, server: String)
}

public enum Change: Sendable {
    /// `share` places a new item in that share; existing items stay where they are.
    case put(id: String?, item: Item, share: String? = nil)
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
    /// Which share each shared item is in; personal items aren't listed.
    private var itemShare: [String: String] = [:]
    private var shareInfo: [String: Share] = [:]
    private var shareKeys: [String: Data] = [:]
    private var sharePriv: Data?
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
            clearDecrypted()
            return
        }
        var out: [String: Item] = [:]
        for (id, r) in s.items {
            if let d = r.data, let it = try? StoriiCrypto.decryptItem(vaultKey: key, id: id, data: d) { out[id] = it }
        }
        var whereIs: [String: String] = [:], info: [String: Share] = [:], keys: [String: Data] = [:]
        sharePriv = s.sealedPrivateKey.isEmpty ? nil : try? ShareCrypto.openPrivateKey(vaultKey: key, sealed: s.sealedPrivateKey)
        if let priv = sharePriv {
            for (sid, sh) in s.shares {
                guard let k = try? ShareCrypto.unwrapShareKey(priv: priv, shareID: sid, wrapped: sh.wrappedKey) else { continue }
                keys[sid] = k
                let name = (try? ShareCrypto.openMeta(shareKey: k, shareID: sid, data: sh.meta).name) ?? ""
                info[sid] = Share(id: sid, name: name, owner: sh.owner, members: sh.members,
                                  mine: sh.owner.lowercased() == s.username.lowercased())
                for (id, r) in sh.items where out[id] == nil {  // the same id in two places: the personal copy wins
                    if let d = r.data, let it = try? ShareCrypto.decryptItem(shareKey: k, shareID: sid, id: id, data: d) {
                        out[id] = it
                        whereIs[id] = sid
                    }
                }
            }
        }
        items = out
        itemShare = whereIs
        shareInfo = info
        shareKeys = keys
    }

    private func clearDecrypted() {
        items = [:]
        itemShare = [:]
        shareInfo = [:]
        shareKeys = [:]
        sharePriv = nil
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
        try? await setupSharing()
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
        clearDecrypted()
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
        out.publicKey = acct.publicKey
        out.sealedPrivateKey = acct.sealedPrivateKey
        out.shares = try await pullShares(api, s.shares)
        return out
    }

    /// Follows the shares list: new shares are fetched whole, changed ones from their revision, gone ones dropped.
    private static func pullShares(_ api: API, _ old: [String: ShareState]) async throws -> [String: ShareState] {
        let list: [RemoteShare]
        do {
            list = try await api.shares()
        } catch let e as APIError where e.status == 404 {
            return [:]  // a server from before sharing
        }
        var out: [String: ShareState] = [:]
        for r in list {
            var sh = old[r.id].flatMap { $0.wrappedKey == r.wrappedKey ? $0 : nil } ?? ShareState(owner: r.owner, meta: r.meta, wrappedKey: r.wrappedKey)
            sh.owner = r.owner
            sh.meta = r.meta
            sh.members = r.members
            if r.revision != sh.revision {
                let sync = try await api.shareSync(r.id, since: sh.revision)
                if sh.revision == 0 { sh.items = [:] }
                for it in sync.items {
                    if it.deleted { sh.items[it.id] = nil } else { sh.items[it.id] = it }
                }
                sh.revision = sync.revision
            }
            out[r.id] = sh
        }
        return out
    }

    /// Creates this account's sharing key pair if it has none yet, so others can add it to shares.
    private func setupSharing() async throws {
        guard let s = state, let key = vaultKey, s.publicKey.isEmpty else { return }
        let pair = ShareCrypto.newKeyPair()
        let api = API(s.server, token: s.token)
        let acct: Account
        do {
            acct = try await api.setShareKeys(publicKey: pair.pub.base64EncodedString(),
                                              sealedPrivateKey: ShareCrypto.sealPrivateKey(vaultKey: key, priv: pair.priv))
        } catch let e as APIError where e.status == 404 {
            return  // a server from before sharing
        } catch let e as APIError where e.status == 409 {
            acct = try await api.account()  // another device got there first
        }
        var x = state ?? s
        x.publicKey = acct.publicKey
        x.sealedPrivateKey = acct.sealedPrivateKey
        try save(x)
        decryptAll()
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
        try? await setupSharing()
        onChange?()
    }

    /// Uploads changes and applies them locally. Returns the ids, new ones included.
    @discardableResult
    public func write(_ changes: [Change]) async throws -> [String] {
        guard state != nil else { throw StoriiError("Not set up") }
        guard let key = vaultKey else { throw StoriiError("Locked") }
        let now = Item.now()
        var writes: [Write] = []
        var place: [String: String] = [:]
        for ch in changes {
            switch ch {
            case .delete(let id):
                writes.append(Write(id: id, delete: true))
                place[id] = itemShare[id] ?? ""
            case .put(let id, var item, let share):
                try item.validate()
                let id = id ?? UUID().uuidString.lowercased()
                let sid = items[id] != nil ? itemShare[id] ?? "" : share ?? ""
                place[id] = sid
                if item.createdAt == nil { item.createdAt = now }
                item.updatedAt = now
                if let prev = items[id] { item = PasswordHistory.apply(prev: prev, next: item, now: now) }
                writes.append(Write(id: id, data: try encrypt(key, sid, id, item)))
            }
        }
        defer {
            decryptAll()
            onChange?()
        }
        try await send(writes) { place[$0] ?? "" }
        return writes.map(\.id)
    }

    private func encrypt(_ vaultKey: Data, _ shareID: String, _ id: String, _ item: Item) throws -> String {
        if shareID.isEmpty { return try StoriiCrypto.encryptItem(vaultKey: vaultKey, id: id, item: item) }
        guard let k = shareKeys[shareID] else { throw StoriiError("No such share") }
        return try ShareCrypto.encryptItem(shareKey: k, shareID: shareID, id: id, item: item)
    }

    /// Uploads writes to the personal vault or the share `place` names, keeping each chunk on disk once it's stored. The
    /// server takes at most 2000 writes per request (a big import has more).
    private func send(_ writes: [Write], place: (String) -> String) async throws {
        var groups: [String: [Write]] = [:], order: [String] = []
        for w in writes {
            let p = place(w.id)
            if groups[p] == nil { order.append(p) }
            groups[p, default: []].append(w)
        }
        for sid in order {
            let ws = groups[sid]!
            for start in stride(from: 0, to: ws.count, by: 1000) {
                let chunk = Array(ws[start..<min(start + 1000, ws.count)])
                guard let s0 = state else { throw StoriiError("Not set up") }
                let api = API(s0.server, token: s0.token)
                let rev = sid.isEmpty ? try await api.write(chunk) : try await api.shareWrite(sid, chunk)
                // Another write may have landed while this one was in flight; start from the newest state.
                guard var s = state else { throw StoriiError("Not set up") }
                func apply(_ m: inout [String: RemoteItem]) {
                    for w in chunk {
                        if w.delete { m[w.id] = nil } else { m[w.id] = RemoteItem(id: w.id, data: w.data, revision: rev) }
                    }
                }
                if sid.isEmpty {
                    apply(&s.items)
                } else if s.shares[sid] != nil {
                    apply(&s.shares[sid]!.items)
                }
                try save(s)
            }
        }
    }

    @discardableResult
    public func put(_ id: String?, _ item: Item) async throws -> String { try await write([.put(id: id, item: item)])[0] }

    /// A deleted item from the server's trash, with its ciphertext so a restore puts back exactly what was there.
    public struct Deleted: Identifiable, Sendable {
        public let id: String
        public let item: Item
        public let deletedAt: Date?
        let data: String
    }

    /// The trash, decrypted (entries this vault key can't read are left out), and how many days it keeps items.
    public func trash() async throws -> (items: [Deleted], days: Int) {
        guard let s = state else { throw StoriiError("Not set up") }
        guard let key = vaultKey else { throw StoriiError("Locked") }
        let t = try await API(s.server, token: s.token).trash()
        let iso = ISO8601DateFormatter()
        let isoFrac = ISO8601DateFormatter()
        isoFrac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let out = t.items.compactMap { d -> Deleted? in
            guard let item = try? StoriiCrypto.decryptItem(vaultKey: key, id: d.id, data: d.data) else { return nil }
            return Deleted(id: d.id, item: item, deletedAt: isoFrac.date(from: d.deleted_at) ?? iso.date(from: d.deleted_at), data: d.data)
        }
        return (out, t.days)
    }

    /// Puts deleted items back under their ids, as they were.
    public func restore(_ deleted: [Deleted]) async throws {
        guard var s = state else { throw StoriiError("Not set up") }
        guard vaultKey != nil else { throw StoriiError("Locked") }
        defer {
            decryptAll()
            onChange?()
        }
        let writes = deleted.map { Write(id: $0.id, data: $0.data) }
        for start in stride(from: 0, to: writes.count, by: 1000) {
            let chunk = Array(writes[start..<min(start + 1000, writes.count)])
            let rev = try await API(s.server, token: s.token).write(chunk)
            s = state ?? s
            for w in chunk { s.items[w.id] = RemoteItem(id: w.id, data: w.data, revision: rev) }
            try save(s)
        }
    }

    /// An encrypted backup of every item, sealed with `password`.
    public func backup(password: String) async throws -> Data {
        guard let s = state else { throw StoriiError("Not set up") }
        guard let key = vaultKey else { throw StoriiError("Locked") }
        var plain: [String: Data] = [:]
        for (id, r) in s.items {
            if let d = r.data, let p = try? StoriiCrypto.open(key: key, data: d, aad: "storii:item:\(id)") { plain[id] = p }
        }
        // Shared items too: a backup holds everything this vault shows.
        for (id, sid) in itemShare {
            if let d = s.shares[sid]?.items[id]?.data, let k = shareKeys[sid],
               let p = try? ShareCrypto.openItem(shareKey: k, shareID: sid, id: id, data: d) { plain[id] = p }
        }
        let items = plain
        return try await Task.detached { try Backup.seal(password: password, items: items) }.value  // Argon2id: off the main actor
    }

    /// Opens a backup and says what restoring it would add (items this vault doesn't have) and skip.
    public func planRestore(password: String, file: Data) async throws -> Backup.Plan {
        guard state != nil else { throw StoriiError("Not set up") }
        let have = Set(items.keys)
        return try await Task.detached { Backup.plan(try Backup.open(password: password, file: file), have: have) }.value
    }

    /// Adds `plan`'s items exactly as they were backed up, under their ids. Returns how many.
    @discardableResult
    public func restoreBackup(_ plan: Backup.Plan) async throws -> Int {
        guard var s = state else { throw StoriiError("Not set up") }
        guard let key = vaultKey else { throw StoriiError("Locked") }
        defer {
            decryptAll()
            onChange?()
        }
        let writes = try plan.add.filter { items[$0.id] == nil }
            .map { Write(id: $0.id, data: try StoriiCrypto.encryptRaw(vaultKey: key, id: $0.id, plaintext: $0.raw)) }
        for start in stride(from: 0, to: writes.count, by: 1000) {
            let chunk = Array(writes[start..<min(start + 1000, writes.count)])
            let rev = try await API(s.server, token: s.token).write(chunk)
            s = state ?? s
            for w in chunk { s.items[w.id] = RemoteItem(id: w.id, data: w.data, revision: rev) }
            try save(s)
        }
        return writes.count
    }

    /// Forgets deleted items for good: `ids`, or everything in the trash when it's empty.
    public func emptyTrash(_ ids: [String] = []) async throws {
        guard let s = state else { throw StoriiError("Not set up") }
        try await API(s.server, token: s.token).emptyTrash(ids)
    }

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

    // MARK: sharing

    /// This account's key fingerprint, for others to compare when they add it; empty before sharing is set up.
    public var fingerprint: String {
        guard let k = state?.publicKey, let pub = Data(base64Encoded: k), !k.isEmpty else { return "" }
        return ShareCrypto.fingerprint(pub)
    }

    public func shares() -> [Share] {
        shareInfo.values.sorted { ($0.name.lowercased(), $0.id) < ($1.name.lowercased(), $1.id) }
    }

    /// The share an item is in, or nil for the personal vault.
    public func shareOf(_ id: String) -> Share? { itemShare[id].flatMap { shareInfo[$0] } }
    public var username: String { state?.username ?? "" }

    private func needSharing() async throws -> Data {
        if sharePriv == nil { try await setupSharing() }
        guard let p = sharePriv else { throw StoriiError("Sharing isn't set up: the server may be too old.") }
        return p
    }

    private func api() throws -> API {
        guard let s = state else { throw StoriiError("Not set up") }
        return API(s.server, token: s.token)
    }

    @discardableResult
    public func createShare(name: String) async throws -> Share {
        let priv = try await needSharing()
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !n.isEmpty else { throw StoriiError("A share needs a name.") }
        let id = UUID().uuidString.lowercased(), key = StoriiCrypto.randomBytes(32)
        let wrapped = try ShareCrypto.wrapShareKey(recipientPub: ShareCrypto.publicKey(of: priv), shareID: id, shareKey: key)
        let meta = try ShareCrypto.sealMeta(shareKey: key, shareID: id, meta: ShareMeta(name: n))
        try await api().createShare(id: id, meta: meta, wrappedKey: wrapped)
        guard var s = state else { throw StoriiError("Not set up") }
        s.shares[id] = ShareState(owner: s.username, meta: meta, wrappedKey: wrapped,
                                  members: [ShareMember(username: s.username, publicKey: s.publicKey, owner: true)])
        try save(s)
        decryptAll()
        onChange?()
        guard let sh = shareInfo[id] else { throw StoriiError("No such share") }
        return sh
    }

    public func renameShare(_ id: String, name: String) async throws {
        guard let key = shareKeys[id] else { throw StoriiError("No such share") }
        let meta = try ShareCrypto.sealMeta(shareKey: key, shareID: id, meta: ShareMeta(name: name.trimmingCharacters(in: .whitespacesAndNewlines)))
        try await api().renameShare(id, meta: meta)
        guard var s = state else { return }
        s.shares[id]?.meta = meta
        try save(s)
        decryptAll()
        onChange?()
    }

    /// Someone's public key and its fingerprint, to compare with them before adding them.
    public func memberKey(_ username: String) async throws -> (username: String, publicKey: String, fingerprint: String) {
        let k = try await api().userKey(username.trimmingCharacters(in: .whitespacesAndNewlines))
        guard let pub = Data(base64Encoded: k.publicKey), pub.count == 32 else { throw StoriiError("The server sent a malformed key.") }
        return (k.username, k.publicKey, ShareCrypto.fingerprint(pub))
    }

    public func addMember(_ id: String, username: String, publicKey: String) async throws {
        guard let key = shareKeys[id] else { throw StoriiError("No such share") }
        guard let pub = Data(base64Encoded: publicKey) else { throw StoriiError("Malformed key") }
        try await api().addShareMember(id, username: username, wrappedKey: ShareCrypto.wrapShareKey(recipientPub: pub, shareID: id, shareKey: key))
        try await sync()
    }

    /// Takes someone out of a share. They keep whatever they copied before.
    public func removeMember(_ id: String, username: String) async throws {
        try await api().removeShareMember(id, username: username)
        try await sync()
    }

    /// Deletes a share with its items (owner) or leaves it (members).
    public func deleteShare(_ id: String) async throws {
        try await api().deleteShare(id)
        guard var s = state else { return }
        s.shares[id] = nil
        try save(s)
        decryptAll()
        onChange?()
    }

    /// Puts items into a share (`shareID` "" = the personal vault) under the same ids. Contexts a moved secret links go
    /// along when nothing staying behind uses them; otherwise the secret gets a copy. Writes the new place first, so a
    /// failure halfway leaves a copy rather than nothing.
    public func move(_ ids: [String], to shareID: String) async throws {
        guard let key = vaultKey else { throw StoriiError("Locked") }
        if !shareID.isEmpty, shareKeys[shareID] == nil { throw StoriiError("No such share") }
        var moving = Set<String>()
        for id in ids where (itemShare[id] ?? "") != shareID {
            guard items[id] != nil else { throw StoriiError("No such item \(id)") }
            moving.insert(id)
        }
        var out: [String: Item] = [:]
        for id in moving { out[id] = items[id] }
        for id in Array(moving) {
            guard var it = out[id], it.isSecret else { continue }
            for (i, c) in it.contexts.enumerated() {
                if moving.contains(c) || (itemShare[c] ?? "") == shareID { continue }
                guard let ctx = items[c] else { continue }
                let usedElsewhere = items.contains { !moving.contains($0.key) && $0.value.contexts.contains(c) }
                if !usedElsewhere {
                    moving.insert(c)
                    out[c] = ctx
                } else {
                    let copy = UUID().uuidString.lowercased()
                    var x = ctx
                    x.createdAt = nil
                    out[copy] = x
                    it.contexts[i] = copy
                }
            }
            out[id] = it
        }
        if out.isEmpty { return }
        let now = Item.now()
        var from: [String: String] = [:]
        for id in moving { from[id] = itemShare[id] ?? "" }
        let puts = try out.sorted { $0.key < $1.key }.map { id, it -> Write in
            var x = it
            if x.createdAt == nil { x.createdAt = now }
            return Write(id: id, data: try encrypt(key, shareID, id, x))
        }
        defer {
            decryptAll()
            onChange?()
        }
        try await send(puts) { _ in shareID }
        try await send(from.keys.sorted().map { Write(id: $0, delete: true) }) { from[$0] ?? "" }
        // A moved item isn't deleted: keep it out of the personal trash, where restoring it would duplicate it.
        let personalGone = from.filter { $0.value.isEmpty }.map(\.key)
        if !personalGone.isEmpty { try? await api().emptyTrash(personalGone) }
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
