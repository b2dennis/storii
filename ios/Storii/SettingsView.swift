import AuthenticationServices
import StoriiCore
import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @State private var autofillOn = false
    @State private var biometrics = Biometrics.enabled
    @State private var askPassword = false
    @State private var password = ""
    @State private var lockMinutes = AppModel.lockMinutes
    @State private var confirmLogout = false
    @State private var message: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    LabeledContent("AutoFill", value: autofillOn ? "On" : "Off")
                    if !autofillOn {
                        Button("Turn on storii AutoFill") {
                            Task {
                                _ = await ASSettingsHelper.requestToTurnOnCredentialProviderExtension()
                                await checkAutofill()
                            }
                        }
                    }
                } header: { Text("AutoFill") } footer: {
                    Text("storii fills passwords and 2FA codes in Safari and apps, for the websites in each secret's contexts. "
                        + "You can also turn it on in \(Platform.autofillSettingsPath).")
                }
                Section {
                    if Biometrics.available {
                        Toggle("Unlock with \(Biometrics.name)", isOn: Binding(get: { biometrics }, set: { on in
                            if on { askPassword = true } else { Biometrics.forget(); biometrics = false }
                        }))
                    }
                    Picker("Lock after", selection: $lockMinutes) {
                        Text("1 minute").tag(1)
                        Text("5 minutes").tag(5)
                        Text("15 minutes").tag(15)
                        Text("1 hour").tag(60)
                        Text("Never").tag(0)
                    }
                    .onChange(of: lockMinutes) { _, m in AppModel.lockMinutes = m }
                    Button("Lock now") { model.lock() }
                } header: { Text("Unlocking") } footer: { Text("How long storii may stay unlocked in the background.") }
                Section("Account") {
                    LabeledContent("User", value: model.username)
                    LabeledContent("Server", value: model.server)
                    Button("Sync now") { Task { await model.sync(); message = model.error ?? "Up to date." } }
                    Button("Log out of this device", role: .destructive) { confirmLogout = true }
                }
                if let m = message { Text(m).foregroundStyle(.secondary) }
            }
            .formStyle(.grouped)
            .navigationTitle("Settings")
            .task { await checkAutofill() }
            .alert("Master password", isPresented: $askPassword) {
                SecureField("Master password", text: $password)
                Button("Continue") { enableBiometrics() }
                Button("Cancel", role: .cancel) { password = "" }
            } message: { Text("Confirm it once to turn on \(Biometrics.name).") }
            .confirmationDialog("Log out?", isPresented: $confirmLogout, titleVisibility: .visible) {
                Button("Log out", role: .destructive) { Task { await model.logout() } }
            } message: { Text("The local copy of the vault is removed from this device. Your secrets stay on the server.") }
        }
    }

    private func checkAutofill() async {
        autofillOn = await ASCredentialIdentityStore.shared.state().isEnabled
        if autofillOn { await Identities.update(model.vault) }
    }

    /// Asking for the master password here means a picked-up unlocked phone can't turn biometrics on silently.
    private func enableBiometrics() {
        let pw = password
        password = ""
        Task {
            guard await model.unlock(password: pw), let key = model.vault.key else {
                message = model.error
                return
            }
            do {
                try Biometrics.save(key: key, account: model.username, server: model.server)
                biometrics = true
            } catch {
                message = error.localizedDescription
            }
        }
    }
}
