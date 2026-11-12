import AuthenticationServices
import StoriiCore
import SwiftUI

/// A passkey request from the system: save a new passkey, or sign in with one (picked here or in QuickType).
enum PasskeyRequest {
    case register(rpId: String, userName: String, userHandle: Data, clientDataHash: Data)
    case assert(rpId: String, clientDataHash: Data, allowed: [Data], recordID: String?)
}

struct PasskeyView: View {
    @Environment(AppModel.self) private var model
    let request: PasskeyRequest
    let finish: (CredentialProviderViewController.Result) -> Void
    @State private var error: String?
    @State private var busy = false

    var body: some View {
        VStack(spacing: 0) {
            if case .unlocked = model.status { content.padding() } else { UnlockView(title: "Unlock storii") }
            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { finish(.cancel) }.keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
        .onChange(of: model.status, initial: true) { _, s in
            // A passkey picked in QuickType is used right after unlocking.
            if case .unlocked = s, case .assert(_, _, _, let id?) = request, let e = passkeys.first(where: { $0.id == id }) { use(e) }
        }
    }

    private var passkeys: [Entry] {
        guard case .assert(let rpId, _, let allowed, _) = request else { return [] }
        let ids = Set(allowed.map(Passkey.b64u))
        return model.vault.secrets().filter {
            $0.item.type == Item.passkey && $0.item.field("rp_id") == rpId && (ids.isEmpty || ids.contains($0.item.field("credential_id")))
        }
    }

    @ViewBuilder private var content: some View {
        switch request {
        case .register(let rpId, let userName, _, _):
            VStack(alignment: .leading, spacing: 12) {
                Text("Save a passkey?").font(.title2.bold())
                Text("For \(rpId)" + (userName.isEmpty ? "." : ", as \(userName)."))
                Text("storii keeps it with your passwords and syncs it to your other devices.").font(.caption).foregroundStyle(.secondary)
                if let error { Text(error).foregroundStyle(.red) }
                Button { save() } label: { Text("Save in storii").frame(maxWidth: .infinity) }
                    .buttonStyle(.borderedProminent).disabled(busy)
                Spacer()
            }
        case .assert(let rpId, _, _, _):
            List {
                Section("Passkeys for \(rpId)") {
                    ForEach(passkeys) { e in
                        Button { use(e) } label: {
                            VStack(alignment: .leading) {
                                Text(e.item.name)
                                Text(e.item.field("user_name")).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    if passkeys.isEmpty { Text("storii has no passkey for \(rpId).").foregroundStyle(.secondary) }
                }
                if let error { Text(error).foregroundStyle(.red) }
            }
        }
    }

    private func save() {
        guard case .register(let rpId, let userName, let userHandle, let hash) = request else { return }
        busy = true
        Task {
            do {
                let c = Passkey.create(rpId: rpId, userHandle: userHandle, userName: userName)
                let id = try await model.vault.put(nil, Item.secret(Item.passkey, name: rpId, fields: c.fields))
                try? await model.vault.remember(secretID: id, host: rpId)
                finish(.passkeyRegistration(ASPasskeyRegistrationCredential(relyingParty: rpId, clientDataHash: hash,
                                                                            credentialID: c.credentialID, attestationObject: c.attestationObject)))
            } catch {
                self.error = error.localizedDescription
                busy = false
            }
        }
    }

    private func use(_ e: Entry) {
        guard case .assert(let rpId, let hash, _, _) = request else { return }
        do {
            let a = try Passkey.assert(fields: e.item.fields, clientDataHash: hash)
            finish(.passkeyAssertion(ASPasskeyAssertionCredential(userHandle: a.userHandle, relyingParty: rpId, signature: a.signature,
                                                                  clientDataHash: hash, authenticatorData: a.authenticatorData,
                                                                  credentialID: a.credentialID)))
        } catch {
            self.error = error.localizedDescription
        }
    }
}
