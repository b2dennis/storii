import StoriiCore
import SwiftUI

/// Log in or create an account. Also shown when the session expired (e.g. the master password changed elsewhere).
struct SetupView: View {
    @Environment(AppModel.self) private var model
    @State var server = "https://"
    @State var username = ""
    var expired = false
    @State private var password = ""
    @State private var confirm = ""
    @State private var register = false
    @State private var localError: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    VStack(spacing: 10) {
                        Logo()
                        Text(expired ? "Your session ended. Log in again." : "Your secrets, end-to-end encrypted on your own storii server.")
                            .multilineTextAlignment(.center)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
                }
                if !expired {
                    Picker("", selection: $register) {
                        Text("Log in").tag(false)
                        Text("Create account").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color.clear)
                }
                Section {
                    TextField("Server", text: $server).urlInput()
                    TextField("Username", text: $username).usernameContent().plainInput()
                    SecureField("Master password", text: $password).passwordContent(new: register)
                    if register { SecureField("Repeat master password", text: $confirm).passwordContent(new: true) }
                } footer: {
                    if register {
                        Text("At least 12 characters with three of: lowercase, uppercase, digits, symbols. It can't be recovered: "
                            + "nobody, not even the server, can read your vault without it.")
                    }
                }
                if let e = localError ?? model.error { Text(e).foregroundStyle(.red) }
                Button(action: submit) {
                    HStack {
                        Spacer()
                        if model.busy { ProgressView() } else { Text(register ? "Create account" : "Log in").bold() }
                        Spacer()
                    }
                }
                .disabled(model.busy || username.isEmpty || password.isEmpty || server.count < 9)
            }
            .formStyle(.grouped)
            .frame(maxWidth: 560)
            .navigationTitle("storii")
            .inlineTitle()
        }
    }

    private func submit() {
        localError = nil
        if register {
            if let e = Self.checkMasterPassword(password) { localError = e; return }
            if password != confirm { localError = "The passwords don't match."; return }
        }
        Task {
            if await model.login(server: server, username: username.trimmingCharacters(in: .whitespaces), password: password, register: register) {
                password = ""
                confirm = ""
            }
        }
    }

    /// The same rule as the CLI.
    static func checkMasterPassword(_ p: String) -> String? {
        let classes = [p.contains { $0.isLowercase }, p.contains { $0.isUppercase }, p.contains { $0.isNumber },
                       p.contains { !$0.isLetter && !$0.isNumber }].filter { $0 }.count
        if p.count < 12 || classes < 3 {
            return "Use at least 12 characters with three of: lowercase, uppercase, digits, symbols."
        }
        return nil
    }
}
