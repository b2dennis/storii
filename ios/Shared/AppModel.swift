import AuthenticationServices
import Foundation
import LocalAuthentication
import Observation
import StoriiCore

/// Where the app and the AutoFill extension share state: the vault file and settings live in the app group container.
enum SharedStore {
    /// iOS uses "group.sh.base2.storii"; macOS uses the team-prefixed form, which needs no provisioning there. The
    /// Info.plist of each target says which (StoriiAppGroup).
    static let appGroup = Bundle.main.object(forInfoDictionaryKey: "StoriiAppGroup") as? String ?? "group.sh.base2.storii"

    static var directory: URL {
        if let c = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) { return c }
        // Unsigned builds (Simulator without a team) have no app group; the app still works on its own.
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    }

    static var vaultFile: URL { directory.appendingPathComponent("vault.json") }
    static var defaults: UserDefaults { UserDefaults(suiteName: appGroup) ?? .standard }
}

/// The vault as SwiftUI sees it, for the app and the AutoFill extension.
@MainActor @Observable
final class AppModel {
    let vault = Vault(file: SharedStore.vaultFile)
    private(set) var status: VaultStatus = .notSetUp
    private(set) var items: [String: Item] = [:]
    private(set) var busy = false
    var error: String?
    private var backgroundSince: Date?

    init() {
        vault.onChange = { [weak self] in self?.refresh() }
        refresh()
    }

    private func refresh() {
        status = vault.status
        items = vault.items
    }

    var isUnlocked: Bool { if case .unlocked = status { true } else { false } }
    var secrets: [Entry] { _ = items; return vault.secrets() }
    var contexts: [Entry] { _ = items; return vault.contexts() }
    var username: String { vault.state?.username ?? "" }
    var server: String { vault.state?.server ?? "" }

    /// Runs an action with a busy flag; errors end up in `error`. Returns whether it worked.
    @discardableResult
    func run(_ action: () async throws -> Void) async -> Bool {
        busy = true
        defer { busy = false }
        do {
            try await action()
            error = nil
            return true
        } catch {
            self.error = error.localizedDescription
            return false
        }
    }

    static var deviceName: String { Platform.deviceName }

    func login(server: String, username: String, password: String, register: Bool) async -> Bool {
        await run {
            try await vault.login(server: server, username: username, password: password, register: register, device: Self.deviceName)
            Biometrics.forget()
            await Identities.update(vault)
        }
    }

    func unlock(password: String) async -> Bool {
        await run {
            try await vault.unlock(password: password)
            await Identities.update(vault)
        }
    }

    func unlockWithBiometrics() async -> Bool {
        guard Biometrics.enabled else { return false }
        let ok = await run {
            guard let key = try await Biometrics.load(account: username, server: server) else { return }
            do {
                try vault.unlock(key: key)
            } catch {
                // The key no longer opens the vault (e.g. the master password changed on another device).
                Biometrics.forget()
                throw StoriiError("Face ID is out of date. Unlock with your master password and turn it on again.")
            }
        }
        return ok && vault.isUnlocked
    }

    func lock() { vault.lock() }

    func logout() async {
        await vault.logout()
        Biometrics.forget()
        await Identities.clear()
    }

    func sync() async {
        await run {
            try await vault.sync()
            await Identities.update(vault)
        }
    }

    func put(_ id: String?, _ item: Item) async -> String? {
        var out: String?
        await run {
            out = try await vault.put(id, item)
            await Identities.update(vault)
        }
        return out
    }

    func write(_ changes: [Change]) async -> [String]? {
        var out: [String]?
        await run {
            out = try await vault.write(changes)
            await Identities.update(vault)
        }
        return out
    }

    func delete(_ ids: [String]) async -> Bool {
        await run {
            try await vault.delete(ids)
            await Identities.update(vault)
        }
    }

    // MARK: auto-lock

    static var lockMinutes: Int {
        get { SharedStore.defaults.object(forKey: "lockMinutes") as? Int ?? 5 }
        set { SharedStore.defaults.set(newValue, forKey: "lockMinutes") }
    }

    func enteredBackground() { backgroundSince = Date() }

    /// Locks after the timeout in the background and picks up changes the extension made to the file.
    func becameActive() {
        if let since = backgroundSince, Self.lockMinutes > 0, Date().timeIntervalSince(since) > Double(Self.lockMinutes * 60) {
            vault.lock()
        }
        backgroundSince = nil
        vault.reload()
    }
}

/// The vault key in the Keychain, readable only after Face ID / Touch ID, shared with the extension through the
/// keychain access group (the first in the entitlements). Removed when biometrics change.
enum Biometrics {
    private static let service = "sh.base2.storii.vault-key"

    static var enabled: Bool {
        get { SharedStore.defaults.bool(forKey: "biometrics") }
        set { SharedStore.defaults.set(newValue, forKey: "biometrics") }
    }

    static var available: Bool { LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) }

    static var name: String {
        let c = LAContext()
        _ = c.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return switch c.biometryType {
        case .faceID: "Face ID"
        case .touchID: "Touch ID"
        case .opticID: "Optic ID"
        default: "Biometrics"
        }
    }

    static func save(key: Data, account: String, server: String) throws {
        forget()
        var err: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &err) else {
            throw StoriiError("Can't protect the key with biometrics.")
        }
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "\(account)@\(server)",
            kSecValueData as String: key,
            kSecAttrAccessControl as String: access,
            kSecUseDataProtectionKeychain as String: true, // macOS: the iOS-style keychain, needed for access groups
        ]
        let rc = SecItemAdd(q as CFDictionary, nil)
        guard rc == errSecSuccess else { throw StoriiError("Couldn't save to the Keychain (\(rc)). Is a passcode set?") }
        enabled = true
    }

    /// Shows the Face ID prompt. Nil when cancelled.
    static func load(account: String, server: String) async throws -> Data? {
        let name = "\(account)@\(server)"
        // SecItemCopyMatching blocks while the prompt is up.
        let (rc, data) = await Task.detached { () -> (OSStatus, Data?) in
            let ctx = LAContext()
            ctx.localizedReason = "Unlock storii"
            let q: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: name,
                kSecReturnData as String: true,
                kSecUseAuthenticationContext as String: ctx,
                kSecUseDataProtectionKeychain as String: true,
            ]
            var out: CFTypeRef?
            let rc = SecItemCopyMatching(q as CFDictionary, &out)
            return (rc, out as? Data)
        }.value
        switch rc {
        case errSecSuccess: return data
        case errSecUserCanceled, errSecAuthFailed: return nil
        case errSecItemNotFound:
            enabled = false
            throw StoriiError("\(name) was turned off because your enrolled fingers or faces changed. Unlock with your master password.")
        default: throw StoriiError("Keychain error \(rc)")
        }
    }

    static func forget() {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                       kSecUseDataProtectionKeychain as String: true] as CFDictionary)
        enabled = false
    }
}

/// The list iOS shows above the keyboard (QuickType) and in the AutoFill sheet: user names, hosts and item ids, never
/// secrets. Rebuilt after every change while unlocked.
@MainActor
enum Identities {
    static func update(_ vault: Vault) async {
        let store = ASCredentialIdentityStore.shared
        guard await store.state().isEnabled else { return }
        var out: [any ASCredentialIdentity] = []
        for (e, hosts) in vault.identities() {
            for h in hosts {
                let service = ASCredentialServiceIdentifier(identifier: h, type: .domain)
                if e.item.type == Item.totp {
                    out.append(ASOneTimeCodeCredentialIdentity(serviceIdentifier: service, label: e.item.name, recordIdentifier: e.id))
                } else {
                    out.append(ASPasswordCredentialIdentity(serviceIdentifier: service, user: e.item.field("username"), recordIdentifier: e.id))
                }
            }
        }
        for e in vault.secrets() where e.item.type == Item.passkey {
            guard let cred = Passkey.unb64u(e.item.field("credential_id")) else { continue }
            out.append(ASPasskeyCredentialIdentity(relyingPartyIdentifier: e.item.field("rp_id"), userName: e.item.field("user_name"),
                                                   credentialID: cred, userHandle: Passkey.unb64u(e.item.field("user_handle")) ?? Data(),
                                                   recordIdentifier: e.id))
        }
        try? await store.replaceCredentialIdentities(out)
    }

    static func clear() async {
        try? await ASCredentialIdentityStore.shared.removeAllCredentialIdentities()
    }
}
