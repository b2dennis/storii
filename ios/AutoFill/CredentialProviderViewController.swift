import AuthenticationServices
import StoriiCore
import SwiftUI

/// What iOS asked for.
enum AutoFillRequest {
    /// The user tapped AutoFill or "Passwords…": show the logins for these hosts, and search.
    case passwords(hosts: [String])
    /// iOS 18 one-time code field: show the 2FA codes for these hosts.
    case codes(hosts: [String])
    /// The user picked one of our identities in the QuickType bar: unlock and return it.
    case record(id: String, host: String, code: Bool)
}

/// storii's AutoFill credential provider. It always needs the user (Face ID or master password): the vault key only
/// exists in memory while unlocked, and an extension process starts locked.
final class CredentialProviderViewController: ASCredentialProviderViewController {
    private let model = AppModel()

    private func show(_ request: AutoFillRequest) {
        model.vault.reload()
        host(AutoFillView(request: request, finish: { [weak self] in self?.finish($0) }).environment(model))
    }

    private func show(_ request: PasskeyRequest) {
        model.vault.reload()
        host(PasskeyView(request: request, finish: { [weak self] in self?.finish($0) }).environment(model))
    }

    private func host(_ root: some View) {
        #if os(iOS)
        let host = UIHostingController(rootView: root)
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(host.view)
        host.didMove(toParent: self)
        #else
        let host = NSHostingController(rootView: root.frame(width: 440, height: 420))
        addChild(host)
        host.view.frame = view.bounds
        host.view.autoresizingMask = [.width, .height]
        view.addSubview(host.view)
        preferredContentSize = NSSize(width: 440, height: 420)
        #endif
    }

    private static func hosts(_ ids: [ASCredentialServiceIdentifier]) -> [String] {
        Array(Set(ids.map { Match.host($0.identifier) }.filter { !$0.isEmpty })).sorted()
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.passwords(hosts: Self.hosts(serviceIdentifiers)))
    }

    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        show(.codes(hosts: Self.hosts(serviceIdentifiers)))
    }

    override func provideCredentialWithoutUserInteraction(for credentialRequest: any ASCredentialRequest) {
        extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userInteractionRequired.rawValue))
    }

    // Passkeys (iOS 17 / macOS 14 and later).

    override func prepareInterface(forPasskeyRegistration registrationRequest: any ASCredentialRequest) {
        guard let r = registrationRequest as? ASPasskeyCredentialRequest, let id = r.credentialIdentity as? ASPasskeyCredentialIdentity,
              r.supportedAlgorithms.isEmpty || r.supportedAlgorithms.contains(.ES256) else {
            return finish(.cancel)
        }
        show(.register(rpId: id.relyingPartyIdentifier, userName: id.userName, userHandle: id.userHandle, clientDataHash: r.clientDataHash))
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier],
                                        requestParameters: ASPasskeyCredentialRequestParameters) {
        show(.assert(rpId: requestParameters.relyingPartyIdentifier, clientDataHash: requestParameters.clientDataHash,
                     allowed: requestParameters.allowedCredentials, recordID: nil))
    }

    override func prepareInterfaceToProvideCredential(for credentialRequest: any ASCredentialRequest) {
        if let r = credentialRequest as? ASPasskeyCredentialRequest, let id = r.credentialIdentity as? ASPasskeyCredentialIdentity {
            return show(.assert(rpId: id.relyingPartyIdentifier, clientDataHash: r.clientDataHash, allowed: [], recordID: id.recordIdentifier))
        }
        let identity = credentialRequest.credentialIdentity
        guard let id = identity.recordIdentifier else {
            show(.passwords(hosts: [Match.host(identity.serviceIdentifier.identifier)]))
            return
        }
        show(.record(id: id, host: Match.host(identity.serviceIdentifier.identifier), code: credentialRequest.type == .oneTimeCode))
    }

    override func prepareInterfaceForExtensionConfiguration() {
        extensionContext.completeExtensionConfigurationRequest()
    }

    enum Result {
        case password(user: String, password: String)
        case code(String)
        case passkeyRegistration(ASPasskeyRegistrationCredential)
        case passkeyAssertion(ASPasskeyAssertionCredential)
        case cancel
    }

    private func finish(_ r: Result) {
        switch r {
        case .password(let user, let password):
            extensionContext.completeRequest(withSelectedCredential: ASPasswordCredential(user: user, password: password), completionHandler: nil)
        case .code(let code):
            extensionContext.completeOneTimeCodeRequest(using: ASOneTimeCodeCredential(code: code))
        case .passkeyRegistration(let c):
            extensionContext.completeRegistrationRequest(using: c)
        case .passkeyAssertion(let c):
            extensionContext.completeAssertionRequest(using: c)
        case .cancel:
            extensionContext.cancelRequest(withError: NSError(domain: ASExtensionErrorDomain, code: ASExtensionError.userCanceled.rawValue))
        }
    }
}

struct AutoFillView: View {
    @Environment(AppModel.self) private var model
    let request: AutoFillRequest
    let finish: (CredentialProviderViewController.Result) -> Void
    @State private var query = ""
    @State private var searchAll = false

    private var hosts: [String] {
        switch request {
        case .passwords(let h), .codes(let h): h
        case .record(_, let h, _): [h]
        }
    }

    private var wantsCodes: Bool {
        switch request {
        case .codes: true
        case .record(_, _, let code): code
        case .passwords: false
        }
    }

    var body: some View {
        content
        .onChange(of: model.status) { _, s in
            // A record picked from the QuickType bar is returned right after unlocking.
            if case .unlocked = s, case .record(let id, _, _) = request, let it = model.items[id] { pick(Entry(id: id, item: it)) }
        }
    }

    #if os(iOS)
    private var content: some View {
        NavigationStack {
            Group {
                if case .unlocked = model.status { list } else { UnlockView(title: "Unlock storii") }
            }
            .toolbar { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { finish(.cancel) } } }
            .inlineTitle()
        }
    }
    #else
    /// The macOS sheet has no navigation bar: a search field on top and Cancel at the bottom.
    private var content: some View {
        VStack(spacing: 0) {
            if case .unlocked = model.status {
                TextField("Search", text: $query).textFieldStyle(.roundedBorder).padding(12)
                list
            } else {
                UnlockView(title: "Unlock storii")
            }
            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { finish(.cancel) }.keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
    }
    #endif

    private var types: [String] { wantsCodes ? [Item.totp] : [Item.password] }

    private var list: some View {
        let matching = hosts.flatMap { model.vault.forHost($0) }.filter { types.contains($0.item.type ?? "") }
        let unique = matching.reduce(into: [Entry]()) { acc, e in if !acc.contains(where: { $0.id == e.id }) { acc.append(e) } }
        let others = query.isEmpty && !searchAll ? [] : model.vault.search(query, types: types).filter { e in !unique.contains { $0.id == e.id } }
        return List {
            if !unique.isEmpty {
                Section(hosts.isEmpty ? "Suggested" : "For \(hosts.joined(separator: ", "))") {
                    ForEach(unique) { e in row(e) }
                }
            } else if query.isEmpty {
                Section {
                    Text("Nothing saved for \(hosts.first ?? "this app") yet. Search to pick a secret; storii then remembers it for this site.")
                        .foregroundStyle(.secondary)
                    if !searchAll { Button("Show all") { searchAll = true } }
                }
            }
            if !others.isEmpty {
                Section("All secrets") { ForEach(others) { e in row(e) } }
            }
        }
        #if os(iOS)
        .searchable(text: $query, placement: .navigationBarDrawer(displayMode: .always))
        .navigationTitle(wantsCodes ? "2FA codes" : "Passwords")
        #endif
    }

    private func row(_ e: Entry) -> some View {
        Button { pick(e) } label: {
            HStack(spacing: 12) {
                TypeIcon(type: e.item.type)
                VStack(alignment: .leading) {
                    Text(e.item.name).foregroundStyle(.primary)
                    let sub = e.item.type == Item.totp ? e.item.field("account") : e.item.field("username")
                    if !sub.isEmpty { Text(sub).font(.caption).foregroundStyle(.secondary) }
                }
                Spacer()
                if e.item.type == Item.totp { TOTPCode(fields: e.item.fields) }
            }
        }
    }

    private func pick(_ e: Entry) {
        Task {
            // Picked by searching: link it to this site so it's suggested next time. Best effort, and never for long.
            if let host = hosts.first, !host.isEmpty, !model.vault.forHost(host).contains(where: { $0.id == e.id }) {
                let vault = model.vault
                let remember = Task { @MainActor in try? await vault.remember(secretID: e.id, host: host) }
                let timeout = Task { try? await Task.sleep(for: .seconds(3)); remember.cancel() }
                _ = await remember.value
                timeout.cancel()
            }
            if e.item.type == Item.totp {
                finish(.code((try? e.item.secretValue()) ?? ""))
            } else {
                finish(.password(user: e.item.field("username"), password: e.item.field("password")))
            }
        }
    }
}
