import Foundation
import XCTest
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import StoriiCore

/// testdata/passkey.json: a passkey made by the browser extension must sign in the same way here.
final class PasskeyTests: XCTestCase {
    func testSharedVector() throws {
        let url = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../testdata/passkey.json").standardized
        let v = try JSONSerialization.jsonObject(with: Data(contentsOf: url)) as! [String: Any]
        let fields = v["passkey"] as! [String: String]
        let clientData = Passkey.unb64u(v["client_data_json"] as! String)!
        let hash = Data(SHA256.hash(data: clientData))
        let a = try Passkey.assert(fields: fields, clientDataHash: hash)
        XCTAssertEqual(Passkey.b64u(a.authenticatorData), v["authenticator_data"] as! String)
        let pub = try P256.Signing.PublicKey(derRepresentation: Passkey.unb64u(v["public_key"] as! String)!)
        XCTAssertTrue(pub.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: a.signature), for: a.authenticatorData + hash))
        XCTAssertEqual(a.userHandle, Data([7, 7, 7]))
    }

    func testCreatedSignsIn() throws {
        let c = Passkey.create(rpId: "example.com", userHandle: Data([1]), userName: "me")
        let hash = Data(SHA256.hash(data: Data("cd".utf8)))
        let a = try Passkey.assert(fields: c.fields, clientDataHash: hash)
        XCTAssertEqual(a.credentialID, c.credentialID)
        XCTAssertEqual(c.attestationObject.prefix(1), Data([0xA3])) // a map of three
    }
}
