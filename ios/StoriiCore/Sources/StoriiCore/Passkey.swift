import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Passkeys with storii as the authenticator, as the extension's src/lib/passkey.js and Android's Passkey.kt (shared
/// vector: testdata/passkey.json): ES256, attestation "none", backed up and synced, sign count 0. On Apple
/// platforms the system builds the client data and hands over its hash.
public enum Passkey {
    static let aaguid = Data("d1a8c0b05f2e4c3b9a7e73746f726969".chunked2().map { UInt8($0, radix: 16)! })
    static let flags: UInt8 = 0x01 | 0x04 | 0x08 | 0x10 // user present, user verified, backup eligible, backed up

    public static func b64u(_ d: Data) -> String {
        d.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func unb64u(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        t += String(repeating: "=", count: (4 - t.count % 4) % 4)
        return Data(base64Encoded: t)
    }

    /// The CBOR WebAuthn needs: ints, byte and text strings, maps (entries in the order given).
    enum CBOR { case int(Int), bytes(Data), text(String), map([(CBOR, CBOR)]) }

    static func encode(_ v: CBOR) -> Data {
        var out = Data()
        func head(_ major: UInt8, _ n: UInt64) {
            switch n {
            case ..<24: out.append(major << 5 | UInt8(n))
            case ..<256: out.append(contentsOf: [major << 5 | 24, UInt8(n)])
            case ..<65536: out.append(contentsOf: [major << 5 | 25, UInt8(n >> 8), UInt8(n & 255)])
            default: out.append(contentsOf: [major << 5 | 26, UInt8(n >> 24 & 255), UInt8(n >> 16 & 255), UInt8(n >> 8 & 255), UInt8(n & 255)])
            }
        }
        func enc(_ v: CBOR) {
            switch v {
            case .int(let i): i >= 0 ? head(0, UInt64(i)) : head(1, UInt64(-1 - i))
            case .bytes(let d): head(2, UInt64(d.count)); out.append(d)
            case .text(let s): let d = Data(s.utf8); head(3, UInt64(d.count)); out.append(d)
            case .map(let m): head(5, UInt64(m.count)); for (k, x) in m { enc(k); enc(x) }
            }
        }
        enc(v)
        return out
    }

    static func rpIdHash(_ rpId: String) -> Data { Data(SHA256.hash(data: Data(rpId.utf8))) }

    public struct Created {
        public let fields: [String: String]
        public let credentialID: Data
        public let attestationObject: Data
    }

    /// A new passkey for [rpId]; the fields are stored as the secret's fields.
    public static func create(rpId: String, userHandle: Data, userName: String, displayName: String = "") -> Created {
        let key = P256.Signing.PrivateKey()
        let raw = key.publicKey.x963Representation // 0x04 | x | y
        let cose = encode(.map([(.int(1), .int(2)), (.int(3), .int(-7)), (.int(-1), .int(1)),
                                (.int(-2), .bytes(raw.subdata(in: 1..<33))), (.int(-3), .bytes(raw.subdata(in: 33..<65)))]))
        var credID = Data(count: 16)
        for i in 0..<16 { credID[i] = UInt8.random(in: 0...255) }
        var authData = rpIdHash(rpId)
        authData.append(contentsOf: [flags | 0x40, 0, 0, 0, 0])
        authData.append(aaguid)
        authData.append(contentsOf: [0, UInt8(credID.count)])
        authData.append(credID)
        authData.append(cose)
        let att = encode(.map([(.text("fmt"), .text("none")), (.text("attStmt"), .map([])), (.text("authData"), .bytes(authData))]))
        let fields = ["credential_id": b64u(credID), "rp_id": rpId, "user_handle": b64u(userHandle), "user_name": userName,
                      "user_display_name": displayName, "private_key": b64u(key.derRepresentation)]
        return Created(fields: fields, credentialID: credID, attestationObject: att)
    }

    public struct Assertion {
        public let authenticatorData: Data
        public let signature: Data
        public let credentialID: Data
        public let userHandle: Data
    }

    /// A sign-in: signs authenticator data and the client data hash the system passed in.
    public static func assert(fields: [String: String], clientDataHash: Data) throws -> Assertion {
        guard let pk = unb64u(fields["private_key"] ?? ""), let credID = unb64u(fields["credential_id"] ?? "") else {
            throw StoriiError("This passkey is damaged.")
        }
        let key = try P256.Signing.PrivateKey(derRepresentation: pk)
        var authData = rpIdHash(fields["rp_id"] ?? "")
        authData.append(contentsOf: [flags, 0, 0, 0, 0])
        let sig = try key.signature(for: authData + clientDataHash)
        return Assertion(authenticatorData: authData, signature: sig.derRepresentation, credentialID: credID,
                         userHandle: unb64u(fields["user_handle"] ?? "") ?? Data())
    }
}

private extension String {
    func chunked2() -> [String] { stride(from: 0, to: count, by: 2).map { String(Array(self)[$0..<$0 + 2]) } }
}
