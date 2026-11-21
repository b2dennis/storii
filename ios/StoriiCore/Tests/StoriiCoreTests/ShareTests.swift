import Foundation
import Testing
@testable import StoriiCore

/// testdata/sharing.json, shared with the Go, JS and Kotlin tests.
nonisolated(unsafe) private let v: [String: Any] = {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../../../testdata/sharing.json").standardized
    return try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
}()

private func b64(_ k: String) -> Data { Data(base64Encoded: v[k] as! String)! }
private func s(_ k: String) -> String { v[k] as! String }
private func nonce(_ b: UInt8) -> Data { Data(repeating: b, count: 12) }

@Suite struct ShareVectors {
    @Test func keys() throws {
        let priv = b64("private_key")
        #expect(try ShareCrypto.publicKey(of: priv) == b64("public_key"))
        #expect(ShareCrypto.fingerprint(b64("public_key")) == s("fingerprint"))
        let sealed = try ShareCrypto.sealPrivateKey(vaultKey: b64("vault_key"), priv: priv, nonce: nonce(1))
        #expect(sealed == s("sealed_private_key"))
        #expect(try ShareCrypto.openPrivateKey(vaultKey: b64("vault_key"), sealed: sealed) == priv)
        #expect(throws: DecryptionError.self) { try ShareCrypto.openPrivateKey(vaultKey: b64("share_key"), sealed: sealed) }
    }

    @Test func shareKeyAndItems() throws {
        let sid = s("share_id"), key = b64("share_key"), priv = b64("private_key")
        let wrapped = try ShareCrypto.wrapShareKey(recipientPub: b64("public_key"), shareID: sid, shareKey: key,
                                                   eph: b64("ephemeral_private_key"), nonce: nonce(2))
        #expect(wrapped == s("wrapped_key"))
        #expect(try ShareCrypto.unwrapShareKey(priv: priv, shareID: sid, wrapped: wrapped) == key)
        #expect(throws: DecryptionError.self) { try ShareCrypto.unwrapShareKey(priv: priv, shareID: sid + "x", wrapped: wrapped) }
        #expect(throws: DecryptionError.self) { try ShareCrypto.unwrapShareKey(priv: key, shareID: sid, wrapped: wrapped) }

        #expect(try ShareCrypto.sealMeta(shareKey: key, shareID: sid, meta: ShareMeta(name: "Family"), nonce: nonce(3)) == s("meta_data"))
        #expect(try ShareCrypto.openMeta(shareKey: key, shareID: sid, data: s("meta_data")).name == "Family")

        let id = s("item_id")
        let want = try Item.decode(JSONSerialization.data(withJSONObject: v["item"]!))
        #expect(try ShareCrypto.decryptItem(shareKey: key, shareID: sid, id: id, data: s("item_data")) == want)
        #expect(throws: DecryptionError.self) { try StoriiCrypto.decryptItem(vaultKey: key, id: id, data: s("item_data")) }
        let mine = try ShareCrypto.encryptItem(shareKey: key, shareID: sid, id: id, item: want)
        #expect(try ShareCrypto.decryptItem(shareKey: key, shareID: sid, id: id, data: mine) == want)
    }

    @Test func roundTripWithFreshKeys() throws {
        let alice = ShareCrypto.newKeyPair(), key = StoriiCrypto.randomBytes(32)
        let w = try ShareCrypto.wrapShareKey(recipientPub: alice.pub, shareID: "s", shareKey: key)
        #expect(try ShareCrypto.unwrapShareKey(priv: alice.priv, shareID: "s", wrapped: w) == key)
        #expect(throws: DecryptionError.self) {
            try ShareCrypto.unwrapShareKey(priv: alice.priv, shareID: "s", wrapped: Data(count: 32).base64EncodedString() + "." + w.split(separator: ".")[1])
        }
    }

    @Test func kdfSentInFull() throws {
        let o = try JSONSerialization.jsonObject(with: JSONEncoder().encode(KDF(salt: "c2FsdA=="))) as! [String: Any]
        #expect(o["alg"] as? String == "argon2id" && o["iterations"] as? Int == 3 && o["memory_kib"] as? Int == 65536
                && o["parallelism"] as? Int == 2)
    }
}
