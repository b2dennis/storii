import Foundation

/// The FIDO Credential Exchange Format (CXF 1.0), what iOS 26's credential exchange (ASCredentialImportManager) and
/// Android's credential transfer hand over when the user moves their passwords and passkeys from another app: logins,
/// passkeys, 2FA codes, cards and notes. As Android's CxfImport.kt; shared cases in testdata/import/cxf*.json.
///
/// On iOS the system hands over typed objects rather than JSON; the app turns them into this JSON (see the app's
/// CredentialExchange.swift) so that both paths share one parser.
public enum CxfImport {
    private typealias Obj = [String: Any]

    /// A string, or a number written as one ("digits": 6 → "6").
    private static func s(_ o: Obj?, _ k: String) -> String {
        switch o?[k] {
        case let v as String: return v
        case let v as Int: return String(v)
        case let v as Double: return v == v.rounded() ? String(Int(v)) : String(v)
        case let v as NSNumber: return v.stringValue
        default: return ""
        }
    }

    /// An EditableField's value ({"fieldType": ..., "value": ...}).
    private static func field(_ o: Obj, _ k: String) -> String { s(o[k] as? Obj, "value") }
    private static func arr(_ v: Any?) -> [Any] { v as? [Any] ?? [] }

    /// The CXF header (version, exporter, accounts). A CXP-style envelope with the header in "payload" (an object,
    /// JSON text or base64url JSON) is unwrapped too, in case an exporter sends one.
    static func header(_ data: Data, depth: Int = 0) -> [String: Any]? {
        var d = data
        if d.starts(with: [0xEF, 0xBB, 0xBF]) { d = d.dropFirst(3) }
        guard let root = (try? JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed])) as? Obj else { return nil }
        if root["accounts"] is [Any] { return root }
        if depth > 0 { return nil }
        switch root["payload"] {
        case let p as Obj: return p["accounts"] is [Any] ? p : nil
        case let p as String:
            return header(Data(p.utf8), depth: 1) ?? Import.unb64(p).flatMap { header($0, depth: 1) }
        default: return nil
        }
    }

    public static func parse(_ data: Data) throws -> Import.Parsed {
        guard let root = header(data) else { throw Import.NotAnExport(message: "The other app sent something storii can't read.") }
        var p = Import.Parsed()
        let items = arr(root["accounts"]).flatMap { arr(($0 as? Obj)?["items"]) }.compactMap { $0 as? Obj }
        for item in items {
            let title = s(item, "title").trimmingCharacters(in: .whitespacesAndNewlines)
            let scope = item["scope"] as? Obj
            var url = ""
            if let u = arr(scope?["urls"]).first as? String {
                url = u.trimmingCharacters(in: .whitespacesAndNewlines)
            } else if let app = arr(scope?["androidApps"]).first as? Obj, !s(app, "bundleId").isEmpty {
                url = "android://" + s(app, "bundleId")
            }
            let creds = arr(item["credentials"]).compactMap { $0 as? Obj }
            let note = creds.filter { s($0, "type") == "note" }
                .map { field($0, "content").trimmingCharacters(in: .whitespacesAndNewlines) }
                .filter { !$0.isEmpty }.joined(separator: "\n\n")
            let user = creds.first { s($0, "type") == "basic-auth" }.map { field($0, "username").trimmingCharacters(in: .whitespacesAndNewlines) } ?? ""
            var used = false
            for c in creds {
                switch s(c, "type") {
                case "basic-auth":
                    let pw = field(c, "password")
                    if !pw.isEmpty {
                        p.logins.append(Import.Login(name: title, url: url, username: field(c, "username").trimmingCharacters(in: .whitespacesAndNewlines),
                                                     password: pw, note: note))
                        used = true
                    }
                case "passkey":
                    let rp = s(c, "rpId").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                    do {
                        if rp.isEmpty { throw StoriiError("no website") }
                        var f = try Import.passkey(credentialId: s(c, "credentialId"), key: s(c, "key"), userHandle: s(c, "userHandle"))
                        f["rp_id"] = rp
                        f["user_name"] = s(c, "username")
                        f["user_display_name"] = s(c, "userDisplayName")
                        p.passkeys.append(Import.PasskeyRow(name: title.isEmpty ? rp : title, fields: f))
                    } catch {
                        p.failed.append("\(title.isEmpty ? s(c, "rpId") : title) (passkey: \(error.localizedDescription))")
                    }
                case "totp":
                    do {
                        let issuer = s(c, "issuer"), account = s(c, "username")
                        let t = try TOTP(fields: ["secret": s(c, "secret"), "algorithm": s(c, "algorithm"), "digits": s(c, "digits"),
                                                  "period": s(c, "period"), "issuer": issuer.isEmpty ? title : issuer,
                                                  "account": account.isEmpty ? user : account])
                        p.codes.append(Import.Code(name: !t.issuer.isEmpty ? t.issuer : !t.account.isEmpty ? t.account : "2FA code", totp: t))
                    } catch {
                        p.failed.append("\(title) (2FA code: \(error.localizedDescription))")
                    }
                case "credit-card":
                    // expiryDate is YYYY-MM.
                    let exp = field(c, "expiryDate").trimmingCharacters(in: .whitespaces)
                    let e = Array(exp)
                    let expiry = e.count == 7 && e[4] == "-" && (e[0..<4] + e[5...]).allSatisfy({ $0.isASCII && $0.isNumber })
                        ? Card.normalizeExpiry(String(e[5...]) + "/" + String(e[0..<4])) : ""
                    p.cards.append(Import.CardRow(name: title, cardholder: field(c, "fullName").trimmingCharacters(in: .whitespacesAndNewlines),
                                                  number: Card.digits(field(c, "number")), expiry: expiry,
                                                  cvc: field(c, "verificationNumber").trimmingCharacters(in: .whitespaces), note: note))
                    used = true
                default: break
                }
            }
            // A note on its own (not attached to a login or card) becomes a note in storii.
            if !used && !note.isEmpty { p.notes.append(Import.NoteRow(name: title.isEmpty ? "Note" : title, text: note)) }
        }
        return p
    }
}
