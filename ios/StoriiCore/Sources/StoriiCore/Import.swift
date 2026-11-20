import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Matching imported entries against the vault, as Android's Import/OtpImport/BitwardenImport.build and the CLI's
/// internal/importer (shared cases in testdata/import):
///
/// - a login becomes a password secret with a website or app context (an existing one is reused); one already in the
///   vault (same site, username and password) is skipped, so importing twice is safe; one matching a login without a
///   username fills that username in;
/// - a 2FA code already saved is skipped, the others are linked to a context with a fitting name;
/// - cards are skipped on the same number, passkeys on the same credential id, notes on the same name and text.
public enum Import {
    public struct Login: Equatable, Sendable {
        public var name, url, username, password, note: String
        public init(name: String, url: String, username: String, password: String, note: String = "") {
            self.name = name; self.url = url; self.username = username; self.password = password; self.note = note
        }
    }

    public struct Code: Equatable, Sendable {
        public var name: String
        public var totp: TOTP
    }

    public struct CardRow: Equatable, Sendable {
        public var name, cardholder, number, expiry, cvc, note: String
    }

    public struct PasskeyRow: Equatable, Sendable {
        public var name: String
        public var fields: [String: String]
    }

    public struct NoteRow: Equatable, Sendable {
        public var name, text: String
    }

    /// Everything read from another app's export.
    public struct Parsed: Equatable, Sendable {
        public var logins: [Login] = []
        public var codes: [Code] = []
        public var cards: [CardRow] = []
        public var passkeys: [PasskeyRow] = []
        public var notes: [NoteRow] = []
        /// Entries storii couldn't read, with the reason in brackets.
        public var failed: [String] = []
        public var count: Int { logins.count + codes.count + cards.count + passkeys.count + notes.count }
        public init() {}
    }

    public enum Action: String, Sendable { case add, username, skip, invalid }

    /// What happens to one entry. `id` is the secret written (or the one already there, for a skip).
    public struct Line: Equatable, Sendable {
        public var action: Action
        public var id: String?
        public var name: String
        public var site: String = ""
        /// Added although a login for the same site and username exists (with another password).
        public var differs = false
    }

    public struct Plan: Sendable {
        /// Items to write, in the order they were made (contexts before the secrets that use them).
        public var writes: [(id: String, item: Item)] = []
        public var lines: [Line] = []
        public func count(_ a: Action) -> Int { lines.filter { $0.action == a }.count }
        public subscript(id: String) -> Item? { writes.last { $0.id == id }?.item }
    }

    public struct NotAnExport: LocalizedError {
        public let message: String
        public var errorDescription: String? { message }
    }

    /// Matches `p` against the vault (id → item). `newId` makes ids for new items.
    public static func build(existing: [String: Item], _ p: Parsed, newId: () -> String, now: String = Item.now()) -> Plan {
        var items = existing
        var plan = Plan()
        func put(_ id: String, _ it: Item) {
            items[id] = it
            plan.writes.removeAll { $0.id == id }
            plan.writes.append((id, it))
        }
        func first(_ match: (Item) -> Bool) -> String? { items.keys.sorted().first { match(items[$0]!) } }

        // Logins.
        for r in p.logins {
            if r.password.isEmpty { plan.lines.append(Line(action: .invalid, name: r.name)); continue }
            let s = site(r)
            let name = r.name.isEmpty ? s.description : r.name
            var same: String?, noUser: String?, sameUser: String?
            for id in items.keys.sorted() {
                let it = items[id]!
                guard it.isSecret, it.type == Item.password else { continue }
                if s.isEmpty {
                    if it.name.lowercased() != name.lowercased() || !it.contexts.isEmpty { continue }
                } else if !it.contexts.contains(where: { c in items[c].map { contextFor($0, s) } ?? false }) { continue }
                let u = it.field("username"), pw = it.field("password")
                if u == r.username && pw == r.password { same = id }
                else if u.isEmpty && pw == r.password && !r.username.isEmpty && noUser == nil { noUser = id }
                else if u == r.username && sameUser == nil { sameUser = id }
            }
            if let same {
                plan.lines.append(Line(action: .skip, id: same, name: name, site: s.description))
            } else if let noUser {
                var it = items[noUser]!
                it.fields["username"] = r.username
                it.updatedAt = now
                put(noUser, it)
                plan.lines.append(Line(action: .username, id: noUser, name: name, site: s.description))
            } else {
                var contexts: [String] = []
                if !s.isEmpty {
                    let ctx = first { contextFor($0, s) } ?? {
                        let id = newId()
                        if !s.pkg.isEmpty {
                            put(id, Item(kind: Item.kindContext, name: name, contextType: "app", androidPackages: [s.pkg],
                                         createdAt: now, updatedAt: now))
                        } else {
                            let scheme = r.url.lowercased().hasPrefix("http://") ? "http" : "https"
                            put(id, Item(kind: Item.kindContext, name: s.host, contextType: "website", urls: ["\(scheme)://\(s.host)"],
                                         createdAt: now, updatedAt: now))
                        }
                        return id
                    }()
                    contexts = [ctx]
                }
                var fields = ["password": r.password]
                if !r.username.isEmpty { fields["username"] = r.username }
                let id = newId()
                put(id, Item(kind: Item.kindSecret, name: name, type: Item.password, contexts: contexts, fields: fields,
                             notes: r.note.isEmpty ? nil : r.note, createdAt: now, updatedAt: now))
                plan.lines.append(Line(action: .add, id: id, name: name, site: s.description, differs: sameUser != nil))
            }
        }

        // 2FA codes.
        for r in p.codes {
            let secret = r.totp.fields["secret"]
            if let dup = first({ $0.isSecret && $0.type == Item.totp && (try? TOTP(fields: $0.fields))?.fields["secret"] == secret }) {
                plan.lines.append(Line(action: .skip, id: dup, name: r.name, site: r.totp.account))
                continue
            }
            let ctx = codeContext(items, [r.totp.issuer, r.name])
            let id = newId()
            put(id, Item(kind: Item.kindSecret, name: r.name, type: Item.totp, contexts: ctx.map { [$0] } ?? [], fields: r.totp.fields,
                         createdAt: now, updatedAt: now))
            plan.lines.append(Line(action: .add, id: id, name: r.name, site: r.totp.account))
        }

        // Cards.
        for c in p.cards {
            var name = c.name
            if name.isEmpty {
                let brand = Card.displayBrand(c.number)
                name = "\(brand.isEmpty ? "Card" : brand) \(c.number.suffix(4))".trimmingCharacters(in: .whitespaces)
            }
            if c.number.isEmpty { plan.lines.append(Line(action: .invalid, name: name)); continue }
            if let dup = first({ $0.isSecret && $0.type == Item.card && Card.digits($0.field("number")) == c.number }) {
                plan.lines.append(Line(action: .skip, id: dup, name: name, site: Card.masked(c.number)))
                continue
            }
            var fields = ["number": c.number]
            if !c.cardholder.isEmpty { fields["cardholder"] = c.cardholder }
            if !c.expiry.isEmpty { fields["expiry"] = c.expiry }
            if !c.cvc.isEmpty { fields["cvc"] = c.cvc }
            let id = newId()
            put(id, Item(kind: Item.kindSecret, name: name, type: Item.card, fields: fields, notes: c.note.isEmpty ? nil : c.note,
                         createdAt: now, updatedAt: now))
            plan.lines.append(Line(action: .add, id: id, name: name, site: Card.masked(c.number)))
        }

        // Passkeys.
        for pk in p.passkeys {
            let rp = pk.fields["rp_id"] ?? ""
            if let dup = first({ $0.isSecret && $0.type == Item.passkey && $0.field("credential_id") == pk.fields["credential_id"] }) {
                plan.lines.append(Line(action: .skip, id: dup, name: pk.name, site: rp))
                continue
            }
            let ctx = first { $0.isContext && $0.urls.contains { Match.host($0) == rp } } ?? {
                let id = newId()
                put(id, Item(kind: Item.kindContext, name: rp, contextType: "website", urls: ["https://\(rp)"], createdAt: now, updatedAt: now))
                return id
            }()
            let id = newId()
            put(id, Item(kind: Item.kindSecret, name: pk.name, type: Item.passkey, contexts: [ctx], fields: pk.fields,
                         createdAt: now, updatedAt: now))
            plan.lines.append(Line(action: .add, id: id, name: pk.name, site: rp))
        }

        // Notes.
        for n in p.notes {
            if let dup = first({ $0.isSecret && $0.type == Item.note && $0.name == n.name && ($0.notes ?? "") == n.text }) {
                plan.lines.append(Line(action: .skip, id: dup, name: n.name))
                continue
            }
            let id = newId()
            put(id, Item(kind: Item.kindSecret, name: n.name, type: Item.note, notes: n.text, createdAt: now, updatedAt: now))
            plan.lines.append(Line(action: .add, id: id, name: n.name))
        }
        return plan
    }

    /// Where a login is used: a web host or an Android package.
    struct Site: CustomStringConvertible {
        var host = "", pkg = ""
        var isEmpty: Bool { host.isEmpty && pkg.isEmpty }
        var description: String { pkg.isEmpty ? host : pkg }
    }

    static func site(_ r: Login) -> Site {
        if r.url.lowercased().hasPrefix("android://") {
            var rest = r.url.dropFirst("android://".count)
            if let at = rest.lastIndex(of: "@") { rest = rest[rest.index(after: at)...] }
            return Site(pkg: String(rest.prefix { $0 != "/" }))
        }
        let h = Match.host(r.url)
        if !h.isEmpty { return Site(host: h) }
        if looksLikeDomain(r.name) { return Site(host: Match.host(r.name)) }
        return Site()
    }

    static func contextFor(_ ctx: Item, _ s: Site) -> Bool {
        guard ctx.isContext else { return false }
        if !s.pkg.isEmpty { return ctx.androidPackages.contains(s.pkg) }
        return ctx.urls.contains { Match.host($0) == s.host }
    }

    static func looksLikeDomain(_ s: String) -> Bool {
        if s.contains(where: { " /@".contains($0) }) || !s.contains(".") { return false }
        let tld = s.split(separator: ".", omittingEmptySubsequences: false).last!
        return tld.count >= 2 && tld.allSatisfy { ("a"..."z").contains($0) }
    }

    /// A context for a 2FA code: the first name that matches a context's name or its site's first label.
    static func codeContext(_ items: [String: Item], _ names: [String]) -> String? {
        func norm(_ s: String) -> String { String(s.lowercased().filter { $0.isASCII && ($0.isLetter || $0.isNumber) }) }
        for n in names {
            let want = norm(n)
            if want.isEmpty { continue }
            if let id = items.keys.sorted().first(where: { id in
                let c = items[id]!
                return c.isContext && (norm(c.name) == want || c.urls.contains {
                    norm(String(Match.host($0).prefix { $0 != "." })) == want
                })
            }) { return id }
        }
        return nil
    }

    /// An imported passkey's fields: an ES256 (P-256) key in PKCS#8, credential ids as GUIDs, "b64."-prefixed or
    /// base64url (as Bitwarden and CXF write them).
    public static func passkey(credentialId: String, key: String, userHandle: String) throws -> [String: String] {
        let hex = credentialId.replacingOccurrences(of: "-", with: "")
        var id: Data?
        if credentialId.hasPrefix("b64.") {
            id = unb64(String(credentialId.dropFirst(4)))
        } else if hex.count == 32, credentialId.count == 32 || credentialId.count == 36, hex.allSatisfy(\.isHexDigit) {
            id = Data(stride(from: 0, to: 32, by: 2).map { i in
                UInt8(String(Array(hex)[i..<i + 2]), radix: 16)!
            })
        } else {
            id = unb64(credentialId)
        }
        guard let id, !id.isEmpty else { throw StoriiError("unreadable credential id") }
        guard let der = unb64(key), (try? P256.Signing.PrivateKey(derRepresentation: der)) != nil else {
            throw StoriiError("unreadable key")
        }
        var f = ["credential_id": Passkey.b64u(id), "private_key": Passkey.b64u(der)]
        if !userHandle.isEmpty {
            guard let h = unb64(userHandle) else { throw StoriiError("unreadable user handle") }
            f["user_handle"] = Passkey.b64u(h)
        }
        return f
    }

    /// base64url or standard base64, padded or not.
    static func unb64(_ s: String) -> Data? {
        let t = s.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "=", with: "")
        guard t.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || "-_+/".contains($0)) }) else { return nil }
        return Passkey.unb64u(t.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_"))
    }
}
