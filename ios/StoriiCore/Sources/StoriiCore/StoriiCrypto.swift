import CArgon2
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public struct DecryptionError: LocalizedError, Equatable {
    public init() {}
    public var errorDescription: String? { "Decryption failed (wrong master password or corrupted data)." }
}

public struct KDF: Codable, Equatable, Sendable {
    public var alg: String
    public var salt: String
    public var iterations: Int
    public var memoryKib: Int
    public var parallelism: Int

    public init(alg: String = "argon2id", salt: String, iterations: Int = 3, memoryKib: Int = 65536, parallelism: Int = 2) {
        self.alg = alg
        self.salt = salt
        self.iterations = iterations
        self.memoryKib = memoryKib
        self.parallelism = parallelism
    }

    enum CodingKeys: String, CodingKey {
        case alg, salt, iterations, parallelism
        case memoryKib = "memory_kib"
    }

    public static func new() -> KDF { KDF(salt: StoriiCrypto.randomBytes(16).base64EncodedString()) }
}

/// storii v2 crypto (docs/CRYPTO.md), pinned by testdata/vectors.json.
public enum StoriiCrypto {
    public struct Keys: Sendable {
        public let auth: Data
        public let wrap: Data
        public var authKey: String { auth.base64EncodedString() }
    }

    public static func randomBytes(_ n: Int) -> Data {
        var g = SystemRandomNumberGenerator()
        return Data((0..<n).map { _ in UInt8.random(in: .min ... .max, using: &g) })
    }

    /// Argon2id over the NFC-normalized password, split with HKDF-SHA256. Slow on purpose.
    public static func deriveKeys(password: String, kdf: KDF) throws -> Keys {
        guard kdf.alg == "argon2id", kdf.iterations >= 1, kdf.memoryKib >= 8 * kdf.parallelism, kdf.parallelism >= 1,
              let salt = Data(base64Encoded: kdf.salt) else {
            throw StoriiError("Unsupported key derivation settings.")
        }
        let pw = Array(password.precomposedStringWithCanonicalMapping.utf8)
        var master = [UInt8](repeating: 0, count: 32)
        let rc = pw.withUnsafeBytes { p in
            salt.withUnsafeBytes { s in
                argon2id_hash_raw(UInt32(kdf.iterations), UInt32(kdf.memoryKib), UInt32(kdf.parallelism),
                                  p.baseAddress, pw.count, s.baseAddress, salt.count, &master, master.count)
            }
        }
        guard rc == 0 else { throw StoriiError("Argon2 failed (\(rc)).") }
        defer { _ = master.withUnsafeMutableBytes { $0.initializeMemory(as: UInt8.self, repeating: 0) } }
        return Keys(auth: hkdf(Data(master), info: "storii auth"), wrap: hkdf(Data(master), info: "storii wrap"))
    }

    /// RFC 5869 with an empty salt and one 32-byte block.
    static func hkdf(_ ikm: Data, info: String) -> Data {
        let prk = Data(HMAC<SHA256>.authenticationCode(for: ikm, using: SymmetricKey(data: Data(count: 32))))
        return Data(HMAC<SHA256>.authenticationCode(for: Data(info.utf8) + [1], using: SymmetricKey(data: prk)))
    }

    /// base64(0x01 || nonce(12) || ciphertext || tag(16))
    public static func seal(key: Data, plaintext: Data, aad: String, nonce: Data? = nil) throws -> String {
        let n = try AES.GCM.Nonce(data: nonce ?? randomBytes(12))
        let box = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: n, authenticating: Data(aad.utf8))
        return (Data([1]) + Data(n) + box.ciphertext + box.tag).base64EncodedString()
    }

    public static func open(key: Data, data: String, aad: String) throws -> Data {
        guard let raw = Data(base64Encoded: data), raw.count >= 29, raw.first == 1 else { throw DecryptionError() }
        let b = [UInt8](raw)
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: b[1..<13]), ciphertext: b[13..<(b.count - 16)],
                                            tag: b[(b.count - 16)...])
            return try AES.GCM.open(box, using: SymmetricKey(data: key), authenticating: Data(aad.utf8))
        } catch {
            throw DecryptionError()
        }
    }

    public static func wrapVaultKey(wrap: Data, vaultKey: Data, nonce: Data? = nil) throws -> String {
        try seal(key: wrap, plaintext: vaultKey, aad: "storii:vault-key", nonce: nonce)
    }

    public static func unwrapVaultKey(wrap: Data, wrapped: String) throws -> Data {
        let k = try open(key: wrap, data: wrapped, aad: "storii:vault-key")
        guard k.count == 32 else { throw DecryptionError() }
        return k
    }

    public static func encryptItem(vaultKey: Data, id: String, item: Item, nonce: Data? = nil) throws -> String {
        try seal(key: vaultKey, plaintext: item.json(), aad: "storii:item:\(id)", nonce: nonce)
    }

    public static func encryptRaw(vaultKey: Data, id: String, plaintext: Data, nonce: Data? = nil) throws -> String {
        try seal(key: vaultKey, plaintext: plaintext, aad: "storii:item:\(id)", nonce: nonce)
    }

    public static func decryptItem(vaultKey: Data, id: String, data: String) throws -> Item {
        try Item.decode(open(key: vaultKey, data: data, aad: "storii:item:\(id)"))
    }

    // MARK: password generator, as internal/vault/generate.go

    static let lower = "abcdefghijklmnopqrstuvwxyz", upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", digits = "0123456789"
    static let symbols = "!@#$%^&*.()"

    /// A random password of `length` (at least 4) with at least one character of each enabled class.
    public static func generatePassword(length: Int = 20, symbols withSymbols: Bool = true) -> String {
        let n = max(length, 4)
        let classes = [lower, upper, digits] + (withSymbols ? [symbols] : [])
        let all = Array(classes.joined())
        var g = SystemRandomNumberGenerator()
        while true {
            let out = String((0..<n).map { _ in all[Int.random(in: 0..<all.count, using: &g)] })
            if classes.allSatisfy({ c in out.contains { c.contains($0) } }) { return out }
        }
    }
}

public struct StoriiError: LocalizedError, Equatable {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var errorDescription: String? { message }
}
