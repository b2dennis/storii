import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// RFC 6238 codes and otpauth:// URIs, matching internal/vault/totp.go.
public struct TOTP: Equatable, Sendable {
    public var secret: Data
    public var algorithm: String
    public var digits: Int
    public var period: Int
    public var issuer: String
    public var account: String

    public init(secret: Data, algorithm: String = "SHA1", digits: Int = 6, period: Int = 30, issuer: String = "", account: String = "") {
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.issuer = issuer
        self.account = account
    }

    /// From an item's fields; missing values take the defaults.
    public init(fields f: [String: String]) throws {
        func int(_ k: String, _ def: Int, _ what: String) throws -> Int {
            guard let s = f[k], !s.isEmpty else { return def }
            guard let v = Int(s) else { throw StoriiError("TOTP \(what) must be a number") }
            return v
        }
        self.init(secret: try Base32.decode(f["secret"] ?? ""),
                  algorithm: (f["algorithm"].flatMap { $0.isEmpty ? nil : $0 } ?? "SHA1").uppercased(),
                  digits: try int("digits", 6, "digits"), period: try int("period", 30, "period"),
                  issuer: f["issuer"] ?? "", account: f["account"] ?? "")
        guard ["SHA1", "SHA256", "SHA512"].contains(algorithm) else { throw StoriiError("Unsupported TOTP algorithm \(algorithm)") }
        guard (6...10).contains(digits) else { throw StoriiError("TOTP digits must be 6 to 10") }
        guard (1...300).contains(period) else { throw StoriiError("TOTP period must be 1 to 300 seconds") }
    }

    public func code(at date: Date = Date()) -> String {
        let counter = UInt64(max(0, Int64(date.timeIntervalSince1970.rounded(.down)) / Int64(period)))
        let msg = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)
        let sum: [UInt8] = switch algorithm {
        case "SHA256": Array(HMAC<SHA256>.authenticationCode(for: msg, using: key))
        case "SHA512": Array(HMAC<SHA512>.authenticationCode(for: msg, using: key))
        default: Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
        }
        let off = Int(sum[sum.count - 1] & 0x0f)
        let v = (UInt64(sum[off]) & 0x7f) << 24 | UInt64(sum[off + 1]) << 16 | UInt64(sum[off + 2]) << 8 | UInt64(sum[off + 3])
        var mod: UInt64 = 1
        for _ in 0..<digits { mod *= 10 }
        let s = String(v % mod)
        return String(repeating: "0", count: max(0, digits - s.count)) + s
    }

    /// Seconds until the code changes.
    public func remaining(at date: Date = Date()) -> Int {
        period - Int(Int64(date.timeIntervalSince1970.rounded(.down)) % Int64(period))
    }

    /// Inverse of `init(fields:)`; defaults are left out.
    public var fields: [String: String] {
        var f = ["secret": Base32.encode(secret)]
        if algorithm != "SHA1" { f["algorithm"] = algorithm }
        if digits != 6 { f["digits"] = String(digits) }
        if period != 30 { f["period"] = String(period) }
        if !issuer.isEmpty { f["issuer"] = issuer }
        if !account.isEmpty { f["account"] = account }
        return f
    }

    /// Parses otpauth://totp/Issuer:account?secret=…, what 2FA QR codes contain.
    public init(uri raw: String) throws {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard s.lowercased().hasPrefix("otpauth://") else { throw StoriiError("Not an otpauth:// URI") }
        let rest = String(s.dropFirst("otpauth://".count))
        let slash = rest.firstIndex(of: "/")
        let host = slash.map { String(rest[..<$0]) } ?? String(rest.prefix { $0 != "?" })
        guard host.lowercased() == "totp" else { throw StoriiError("Only TOTP (time-based) codes are supported") }
        let afterHost = slash.map { String(rest[rest.index(after: $0)...]) } ?? ""
        let q = afterHost.firstIndex(of: "?")
        let label = TOTP.percentDecode(q.map { String(afterHost[..<$0]) } ?? afterHost, plusIsSpace: false)
        var query: [String: String] = [:]
        if let q {
            for pair in afterHost[afterHost.index(after: q)...].split(separator: "&") where !pair.isEmpty {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let k = TOTP.percentDecode(String(kv[0]), plusIsSpace: true)
                let v = kv.count > 1 ? TOTP.percentDecode(String(kv[1]), plusIsSpace: true) : ""
                if query[k] == nil { query[k] = v }
            }
        }
        var f = ["secret": query["secret"] ?? "", "algorithm": query["algorithm"] ?? "", "digits": query["digits"] ?? "",
                 "period": query["period"] ?? "", "issuer": query["issuer"] ?? ""]
        if let colon = label.firstIndex(of: ":") {
            if f["issuer"]!.isEmpty { f["issuer"] = label[..<colon].trimmingCharacters(in: .whitespaces) }
            f["account"] = label[label.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        } else {
            f["account"] = label
        }
        try self.init(fields: f)
    }

    /// The otpauth:// URI for this code, e.g. to show it as a QR code again.
    public var uri: String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        func enc(_ s: String) -> String { s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s }
        var label = enc(account)
        if !issuer.isEmpty { label = enc(issuer) + ":" + label }
        var q = "secret=" + Base32.encode(secret)
        if !issuer.isEmpty { q += "&issuer=" + enc(issuer) }
        if algorithm != "SHA1" { q += "&algorithm=" + algorithm }
        if digits != 6 { q += "&digits=\(digits)" }
        if period != 30 { q += "&period=\(period)" }
        return "otpauth://totp/\(label)?\(q)"
    }

    static func percentDecode(_ s: String, plusIsSpace: Bool) -> String {
        var out = [UInt8]()
        let b = Array(s.utf8)
        var i = 0
        while i < b.count {
            if b[i] == UInt8(ascii: "%"), i + 2 < b.count,
               let v = UInt8(String(decoding: b[(i + 1)...(i + 2)], as: UTF8.self), radix: 16) {
                out.append(v)
                i += 3
                continue
            }
            out.append(plusIsSpace && b[i] == UInt8(ascii: "+") ? UInt8(ascii: " ") : b[i])
            i += 1
        }
        return String(decoding: out, as: UTF8.self)
    }
}

public enum Base32 {
    static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    /// Lenient like Go's decoder: case, spaces, dashes and padding are ignored.
    public static func decode(_ input: String) throws -> Data {
        let s = input.uppercased().utf8.filter { $0 != UInt8(ascii: " ") && $0 != UInt8(ascii: "-") && $0 != UInt8(ascii: "=") }
        let bad = StoriiError("TOTP secret is not valid base32")
        guard !s.isEmpty, ![1, 3, 6].contains(s.count % 8) else { throw bad }
        var bits = 0, value = 0
        var out = Data()
        for c in s {
            guard let i = alphabet.firstIndex(of: c) else { throw bad }
            value = (value << 5 | i) & 0xffff
            bits += 5
            if bits >= 8 {
                out.append(UInt8((value >> (bits - 8)) & 0xff))
                bits -= 8
            }
        }
        guard !out.isEmpty else { throw bad }
        return out
    }

    public static func encode(_ data: Data) -> String {
        var out = [UInt8]()
        var bits = 0, value = 0
        for b in data {
            value = (value << 8 | Int(b)) & 0xffff
            bits += 8
            while bits >= 5 {
                out.append(alphabet[(value >> (bits - 5)) & 31])
                bits -= 5
            }
        }
        if bits > 0 { out.append(alphabet[(value << (5 - bits)) & 31]) }
        return String(decoding: out, as: UTF8.self)
    }
}
