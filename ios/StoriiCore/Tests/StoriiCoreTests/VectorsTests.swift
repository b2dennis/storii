import Foundation
import Testing
@testable import StoriiCore

/// testdata/vectors.json, shared with the Go, JS and Kotlin tests.
nonisolated(unsafe) private let vectors: [String: Any] = {
    let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../../../testdata/vectors.json").standardized
    return try! JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
}()

private func list(_ k: String) -> [[String: Any]] { vectors[k] as! [[String: Any]] }
private func b64(_ s: Any?) -> Data { Data(base64Encoded: s as! String)! }
private func kdf(_ o: Any?) -> KDF {
    let d = try! JSONSerialization.data(withJSONObject: o!)
    return try! JSONDecoder().decode(KDF.self, from: d)
}

@Suite struct Vectors {
    @Test func keyDerivation() throws {
        for v in list("kdf") {
            let keys = try StoriiCrypto.deriveKeys(password: v["password"] as! String, kdf: kdf(v["kdf"]))
            #expect(keys.authKey == v["auth_key"] as! String)
            #expect(keys.wrap == b64(v["wrap_key"]))
        }
    }

    @Test func vaultKey() throws {
        let v = vectors["vault_key"] as! [String: Any]
        let wrapped = try StoriiCrypto.wrapVaultKey(wrap: b64(v["wrap_key"]), vaultKey: b64(v["vault_key"]), nonce: b64(v["nonce"]))
        #expect(wrapped == v["wrapped"] as! String)
        #expect(try StoriiCrypto.unwrapVaultKey(wrap: b64(v["wrap_key"]), wrapped: wrapped) == b64(v["vault_key"]))
        #expect(throws: DecryptionError.self) { try StoriiCrypto.unwrapVaultKey(wrap: b64(v["vault_key"]), wrapped: wrapped) }
    }

    @Test func items() throws {
        for v in list("items") {
            let key = b64(v["vault_key"]), id = v["id"] as! String, data = v["data"] as! String
            let plaintext = Data((v["plaintext"] as! String).utf8)
            #expect(try StoriiCrypto.encryptRaw(vaultKey: key, id: id, plaintext: plaintext, nonce: b64(v["nonce"])) == data)
            let item = try StoriiCrypto.decryptItem(vaultKey: key, id: id, data: data)
            #expect(item == (try Item.decode(plaintext)))
            // Our encoding must decode to the same item (all clients read each other's JSON).
            #expect(try Item.decode(item.json()) == item)
            #expect(throws: DecryptionError.self) { try StoriiCrypto.decryptItem(vaultKey: key, id: id + "x", data: data) }
        }
    }

    @Test func totp() throws {
        for v in list("totp") {
            let t = try TOTP(fields: v["fields"] as! [String: String])
            #expect(t.code(at: Date(timeIntervalSince1970: (v["time"] as! NSNumber).doubleValue)) == v["code"] as! String)
        }
    }

    @Test func otpauth() throws {
        for v in list("otpauth") {
            let uri = v["uri"] as! String
            if let fields = v["fields"] as? [String: String] {
                let t = try TOTP(uri: uri)
                #expect(t.fields == (try TOTP(fields: fields)).fields, "\(uri)")
                #expect(try TOTP(uri: t.uri) == t)
            } else {
                #expect(throws: (any Error).self, "\(uri)") { try TOTP(uri: uri) }
            }
        }
    }

    @Test func match() {
        for v in list("match") {
            #expect(Match.matchesHost(contextURL: v["context_url"] as! String, pageHost: v["host"] as! String) == v["match"] as! Bool,
                    "\(v)")
        }
    }
}

@Suite struct Units {
    @Test func base32RoundTrip() throws {
        for n in 1...40 {
            let d = StoriiCrypto.randomBytes(n)
            #expect(try Base32.decode(Base32.encode(d)) == d)
        }
        #expect(try Base32.decode("jbsw y3dp-ehpk3pxp====") == Base32.decode("JBSWY3DPEHPK3PXP"))
        #expect(throws: StoriiError.self) { try Base32.decode("1") }
    }

    @Test func generator() {
        for _ in 0..<50 {
            let p = StoriiCrypto.generatePassword(length: 8, symbols: true)
            #expect(p.count == 8)
            #expect(p.contains { $0.isNumber } && p.contains { $0.isUppercase } && p.contains { $0.isLowercase })
            #expect(p.contains { "!@#$%^&*.()".contains($0) })
        }
    }

    @Test func emptyValuesAreLeftOut() throws {
        let s = String(decoding: try Item.context("GitHub").json(), as: UTF8.self)
        #expect(s == #"{"context_type":"website","kind":"context","name":"GitHub"}"#)
    }

    @Test func validation() {
        #expect(throws: StoriiError.self) { try Item.secret(Item.totp, name: "x", fields: ["secret": "!!"]).validate() }
        #expect(throws: StoriiError.self) { try Item.secret("bogus", name: "x").validate() }
        #expect(throws: StoriiError.self) { try Item.secret(Item.password, name: " ").validate() }
    }
}
