import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// The decrypted description of a share.
public struct ShareMeta: Codable, Equatable, Sendable {
    public var name: String
    public init(name: String) { self.name = name }
}

/// Sharing crypto (docs/CRYPTO.md#sharing), pinned by testdata/sharing.json.
public enum ShareCrypto {
    public static func publicKey(of priv: Data) throws -> Data {
        do {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv).publicKey.rawRepresentation
        } catch {
            throw DecryptionError()
        }
    }

    /// A new X25519 key pair.
    public static func newKeyPair() -> (priv: Data, pub: Data) {
        let k = Curve25519.KeyAgreement.PrivateKey()
        return (k.rawRepresentation, k.publicKey.rawRepresentation)
    }

    public static func sealPrivateKey(vaultKey: Data, priv: Data, nonce: Data? = nil) throws -> String {
        try StoriiCrypto.seal(key: vaultKey, plaintext: priv, aad: "storii:share-private-key", nonce: nonce)
    }

    public static func openPrivateKey(vaultKey: Data, sealed: String) throws -> Data {
        let k = try StoriiCrypto.open(key: vaultKey, data: sealed, aad: "storii:share-private-key")
        guard k.count == 32 else { throw DecryptionError() }
        return k
    }

    /// The first 16 bytes of SHA-256(public key), as 8 groups of 4 hex digits.
    public static func fingerprint(_ pub: Data) -> String {
        let hex = SHA256.hash(data: pub).prefix(16).map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map { i in
            let a = hex.index(hex.startIndex, offsetBy: i)
            return String(hex[a..<hex.index(a, offsetBy: 4)])
        }.joined(separator: " ")
    }

    private static func agree(_ priv: Data, _ pub: Data) throws -> Data {
        guard pub.count == 32 else { throw DecryptionError() }
        do {
            let s = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: priv)
                .sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub))
            let raw = s.withUnsafeBytes { Data($0) }
            guard raw.contains(where: { $0 != 0 }) else { throw DecryptionError() }  // a low-order point
            return raw
        } catch {
            throw DecryptionError()
        }
    }

    private static func wrapKey(_ shared: Data, _ ephPub: Data, _ recipientPub: Data) -> Data {
        StoriiCrypto.hkdf(shared + ephPub + recipientPub, info: "storii share key")
    }

    /// The share key for one member: "base64(ephemeral public key).envelope".
    public static func wrapShareKey(recipientPub: Data, shareID: String, shareKey: Data, eph: Data? = nil, nonce: Data? = nil) throws -> String {
        let e = eph ?? StoriiCrypto.randomBytes(32)
        let ephPub = try publicKey(of: e)
        let key = wrapKey(try agree(e, recipientPub), ephPub, recipientPub)
        return ephPub.base64EncodedString() + "." + (try StoriiCrypto.seal(key: key, plaintext: shareKey, aad: "storii:share-key:\(shareID)", nonce: nonce))
    }

    public static func unwrapShareKey(priv: Data, shareID: String, wrapped: String) throws -> Data {
        guard let dot = wrapped.firstIndex(of: "."), let ephPub = Data(base64Encoded: String(wrapped[..<dot])) else {
            throw DecryptionError()
        }
        let key = wrapKey(try agree(priv, ephPub), ephPub, try publicKey(of: priv))
        let k = try StoriiCrypto.open(key: key, data: String(wrapped[wrapped.index(after: dot)...]), aad: "storii:share-key:\(shareID)")
        guard k.count == 32 else { throw DecryptionError() }
        return k
    }

    public static func sealMeta(shareKey: Data, shareID: String, meta: ShareMeta, nonce: Data? = nil) throws -> String {
        try StoriiCrypto.seal(key: shareKey, plaintext: JSONEncoder().encode(meta), aad: "storii:share:\(shareID)", nonce: nonce)
    }

    public static func openMeta(shareKey: Data, shareID: String, data: String) throws -> ShareMeta {
        let raw = try StoriiCrypto.open(key: shareKey, data: data, aad: "storii:share:\(shareID)")
        guard let m = try? JSONDecoder().decode(ShareMeta.self, from: raw) else { throw DecryptionError() }
        return m
    }

    private static func itemAAD(_ shareID: String, _ id: String) -> String { "storii:share:\(shareID):item:\(id)" }

    public static func encryptItem(shareKey: Data, shareID: String, id: String, item: Item, nonce: Data? = nil) throws -> String {
        try StoriiCrypto.seal(key: shareKey, plaintext: item.json(), aad: itemAAD(shareID, id), nonce: nonce)
    }

    public static func encryptRaw(shareKey: Data, shareID: String, id: String, plaintext: Data, nonce: Data? = nil) throws -> String {
        try StoriiCrypto.seal(key: shareKey, plaintext: plaintext, aad: itemAAD(shareID, id), nonce: nonce)
    }

    public static func openItem(shareKey: Data, shareID: String, id: String, data: String) throws -> Data {
        try StoriiCrypto.open(key: shareKey, data: data, aad: itemAAD(shareID, id))
    }

    public static func decryptItem(shareKey: Data, shareID: String, id: String, data: String) throws -> Item {
        try Item.decode(openItem(shareKey: shareKey, shareID: shareID, id: id, data: data))
    }
}
