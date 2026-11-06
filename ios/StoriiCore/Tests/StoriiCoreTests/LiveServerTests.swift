import Foundation
import Testing
@testable import StoriiCore

/// Round trip against a real server: STORII_E2E_SERVER=http://localhost:9999 swift test --filter LiveServer
@Suite(.enabled(if: ProcessInfo.processInfo.environment["STORII_E2E_SERVER"] != nil))
@MainActor struct LiveServer {
    let server = ProcessInfo.processInfo.environment["STORII_E2E_SERVER"] ?? ""

    func tempFile() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("storii-\(UUID().uuidString)/vault.json")
    }

    @Test func roundTrip() async throws {
        let user = "swift-\(UUID().uuidString.prefix(8).lowercased())"
        let pw = "Swift-Test-Pass-1"
        let a = Vault(file: tempFile())
        try await a.login(server: server, username: user, password: pw, register: true, device: "swift test")
        let ctx = try await a.put(nil, .context("Example", urls: ["https://example.com"]))
        var login = Item.secret(Item.password, name: "Example", fields: ["username": "me", "password": "hunter2"])
        login.contexts = [ctx]
        let loginID = try await a.put(nil, login)
        let otpID = try await a.put(nil, .secret(Item.totp, name: "Example 2FA", fields: ["secret": "JBSWY3DPEHPK3PXP"]))
        try await a.remember(secretID: otpID, host: "login.example.com") // reuses the example.com context
        #expect(Set(a.forHost("www.example.com").map(\.id)) == [loginID, otpID])

        // A second device logs in, sees everything, and works offline after locking.
        let b = Vault(file: tempFile())
        try await b.login(server: server, username: user, password: pw, register: false, device: "swift test 2")
        #expect(b.items == a.items)
        b.lock()
        #expect(b.items.isEmpty)
        let key = try await b.unlock(password: pw)
        #expect(b.get(loginID)?.field("password") == "hunter2")
        await #expect(throws: StoriiError.self) { try await b.unlock(password: "wrong") }

        // Deleting the context unlinks it, and the first device picks that up.
        try await b.delete([ctx])
        try await a.sync()
        #expect(a.get(ctx) == nil)
        #expect(a.get(loginID)?.contexts == [])
        #expect(a.forHost("example.com").isEmpty)
        #expect(a.get(otpID)?.contexts == [])

        // Fresh process over the same file: locked, then unlocks with the kept key.
        let c = Vault(file: b.file)
        #expect(c.status == .locked(username: user, server: API.normalize(server), expired: false))
        try c.unlock(key: key)
        #expect(c.items == b.items)
        await b.logout()
        #expect(!FileManager.default.fileExists(atPath: b.file.path))
    }
}
