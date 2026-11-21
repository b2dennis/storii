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

        // Deleted items wait in the trash, newest first, and a restore puts them back for every device.
        try await a.delete([otpID])
        let (trash, days) = try await a.trash()
        #expect(days == 30)
        #expect(trash.map(\.id) == [otpID, ctx])
        #expect(trash.first?.item.name == "Example 2FA")
        try await a.restore([trash[0]])
        try await b.sync()
        #expect(b.get(otpID)?.field("secret") == "JBSWY3DPEHPK3PXP")
        try await a.emptyTrash()
        #expect(try await a.trash().items.isEmpty)

        // A backup brings back what was deleted since, under the same ids, and skips what's still there.
        let backup = try await a.backup(password: "backup Horse 42")
        try await a.delete([otpID])
        let plan = try await b.planRestore(password: "backup Horse 42", file: backup)
        #expect(plan.add.map(\.id) == [])  // b hasn't synced the delete yet
        try await b.sync()
        let plan2 = try await b.planRestore(password: "backup Horse 42", file: backup)
        #expect(plan2.add.map(\.id) == [otpID])
        #expect(try await b.restoreBackup(plan2) == 1)
        try await a.sync()
        #expect(a.get(otpID)?.field("secret") == "JBSWY3DPEHPK3PXP")
        await #expect(throws: Backup.WrongPassword.self) { try await a.planRestore(password: "nope", file: backup) }

        // Fresh process over the same file: locked, then unlocks with the kept key.
        let c = Vault(file: b.file)
        #expect(c.status == .locked(username: user, server: API.normalize(server), expired: false))
        try c.unlock(key: key)
        #expect(c.items == b.items)
        await b.logout()
        #expect(!FileManager.default.fileExists(atPath: b.file.path))
    }

    @Test func sharing() async throws {
        let tag = UUID().uuidString.prefix(8).lowercased()
        let pw = "Swift-Test-Pass-1"
        let alice = Vault(file: tempFile()), bob = Vault(file: tempFile())
        try await alice.login(server: server, username: "swa-\(tag)", password: pw, register: true, device: "swift test")
        try await bob.login(server: server, username: "swb-\(tag)", password: pw, register: true, device: "swift test")
        #expect(!alice.fingerprint.isEmpty && alice.fingerprint != bob.fingerprint)

        // A secret and its own context; another secret keeps using a second context, so that one is copied instead.
        let site = try await alice.put(nil, .context("Netflix", urls: ["https://netflix.com"]))
        let shared = try await alice.put(nil, .context("Shared site", urls: ["https://example.org"]))
        var login = Item.secret(Item.password, name: "Netflix", fields: ["username": "family", "password": "popcorn"])
        login.contexts = [site, shared]
        let loginID = try await alice.put(nil, login)
        var other = Item.secret(Item.password, name: "Other", fields: ["password": "x"])
        other.contexts = [shared]
        let otherID = try await alice.put(nil, other)

        let family = try await alice.createShare(name: "Family")
        #expect(family.mine && alice.shares().map(\.name) == ["Family"])
        let k = try await alice.memberKey("SWB-\(tag)")
        #expect(k.username == "swb-\(tag)" && k.fingerprint == bob.fingerprint)
        try await alice.addMember(family.id, username: k.username, publicKey: k.publicKey)
        try await alice.move([loginID], to: family.id)
        #expect(alice.shareOf(loginID)?.name == "Family" && alice.shareOf(site)?.id == family.id)
        #expect(alice.shareOf(shared) == nil && alice.shareOf(otherID) == nil)
        let moved = try #require(alice.get(loginID))
        #expect(moved.contexts.count == 2 && moved.contexts[0] == site && moved.contexts[1] != shared)
        #expect(alice.forHost("netflix.com").map(\.id) == [loginID])

        // Bob sees it, and his edit lands in the share.
        try await bob.sync()
        #expect(bob.shares().map(\.name) == ["Family"] && !(bob.shares().first?.mine ?? true))
        #expect(bob.get(loginID)?.field("password") == "popcorn" && bob.forHost("example.org").map(\.id) == [loginID])
        var edit = try #require(bob.get(loginID))
        edit.fields["password"] = "popcorn-2"
        try await bob.put(loginID, edit)
        #expect(bob.shareOf(loginID)?.id == family.id)
        // A new item with a share goes there; one without stays personal.
        let note = try await bob.write([.put(id: nil, item: .secret(Item.note, name: "Wifi", fields: ["note": "pw"]), share: family.id)])[0]
        try await alice.sync()
        #expect(alice.get(loginID)?.field("password") == "popcorn-2" && alice.shareOf(note)?.id == family.id)
        #expect(alice.get(loginID)?.history.count == 1)

        // A backup includes shared items.
        let plan = try await alice.planRestore(password: "b", file: alice.backup(password: "b"))
        #expect(plan.add.isEmpty)

        // Home again: gone for Bob.
        try await alice.move([loginID], to: "")
        #expect(alice.shareOf(loginID) == nil && alice.get(loginID)?.field("password") == "popcorn-2")
        try await bob.sync()
        #expect(bob.get(loginID) == nil && bob.get(note) != nil)

        try await alice.renameShare(family.id, name: "Household")
        try await bob.sync()
        #expect(bob.shares().map(\.name) == ["Household"])
        try await alice.removeMember(family.id, username: k.username)
        try await bob.sync()
        #expect(bob.shares().isEmpty && bob.get(note) == nil)
        try await alice.deleteShare(family.id)
        #expect(alice.shares().isEmpty && alice.get(note) == nil)

        // A fresh process over the same file opens shares after unlocking.
        let again = Vault(file: alice.file)
        _ = try await again.unlock(password: pw)
        #expect(again.items == alice.items)
    }
}
