import StoriiCore
import SwiftUI
import UniformTypeIdentifiers

/// The backup file handed to the share/save sheet.
struct BackupFile: FileDocument {
    static var readableContentTypes: [UTType] { [.json] }
    var data: Data
    init(data: Data) { self.data = data }
    init(configuration: ReadConfiguration) throws { data = configuration.file.regularFileContents ?? Data() }
    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper { FileWrapper(regularFileWithContents: data) }
}

/// Saving an encrypted backup file, and restoring one.
struct BackupsView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @State private var repeated = ""
    @State private var file: BackupFile?
    @State private var saveMessage: String?
    @State private var saveError: String?
    @State private var busy = false
    // Restoring: the chosen file, its password, and what restoring would do.
    @State private var choosing = false
    @State private var chosen: Data?
    @State private var restorePassword = ""
    @State private var plan: Backup.Plan?
    @State private var restoreMessage: String?
    @State private var restoreError: String?

    var body: some View {
        Form {
            Section {
                SecureField("Backup password", text: $password).textContentType(.newPassword)
                SecureField("Repeat it", text: $repeated).textContentType(.newPassword)
                if let saveError { Text(saveError).foregroundStyle(.red) }
                Button(busy && chosen == nil ? "Encrypting…" : "Save backup") { Task { await save() } }.disabled(busy || password.isEmpty)
                if let saveMessage { Text(saveMessage).font(.footnote).foregroundStyle(.secondary) }
            } header: { Text("Save a backup") } footer: {
                Text("One file with all your secrets and contexts, encrypted with a backup password you choose. It opens " +
                     "without the storii server or your account, in the apps, the browser extension or the CLI. Keep the " +
                     "file somewhere safe and the password somewhere else.")
            }
            Section {
                Button(chosen == nil ? "Choose a backup file" : "Choose another file") { choosing = true }
                if chosen != nil, plan == nil {
                    SecureField("Backup password", text: $restorePassword)
                    Button(busy ? "Opening…" : "Open backup") { Task { await open() } }.disabled(busy || restorePassword.isEmpty)
                }
                if let plan {
                    Text("\(plan.add.count) to restore, \(plan.skipped) already in storii.").fontWeight(.semibold)
                    if !plan.add.isEmpty {
                        Text(plan.add.prefix(30).map(\.item.name).joined(separator: ", ") + (plan.add.count > 30 ? ", …" : ""))
                            .font(.footnote).foregroundStyle(.secondary)
                        Button("Restore \(plan.add.count) item\(plan.add.count == 1 ? "" : "s")") { Task { await restore(plan) } }
                            .disabled(busy)
                    }
                }
                if let restoreError { Text(restoreError).foregroundStyle(.red) }
                if let restoreMessage { Text(restoreMessage) }
            } header: { Text("Restore a backup") } footer: {
                Text("Adds the backup's items that aren't in storii, exactly as they were backed up. Items storii already has are left as they are.")
            }
        }
        .navigationTitle("Backups")
        .fileExporter(isPresented: Binding(get: { file != nil }, set: { if !$0 { file = nil } }), document: file,
                      contentType: .json, defaultFilename: "storii-backup-\(Date().formatted(.iso8601.year().month().day())).json") { result in
            switch result {
            case .success:
                password = ""
                repeated = ""
                saveMessage = "Backup saved. Without the backup password it can't be opened."
            case .failure(let e):
                saveError = e.localizedDescription
            }
        }
        .fileImporter(isPresented: $choosing, allowedContentTypes: [.json, .data, .plainText]) { result in
            restoreError = nil
            restoreMessage = nil
            plan = nil
            chosen = nil
            guard case .success(let url) = result else { return }
            let scoped = url.startAccessingSecurityScopedResource()
            defer { if scoped { url.stopAccessingSecurityScopedResource() } }
            guard let data = try? Data(contentsOf: url), data.count <= 50 << 20, Backup.isBackup(data) else {
                restoreError = "That isn't a storii backup. Other password managers' exports go through Import."
                return
            }
            chosen = data
        }
    }

    private func save() async {
        saveMessage = nil
        saveError = SetupView.checkMasterPassword(password) ?? (password != repeated ? "The passwords don't match." : nil)
        guard saveError == nil else { return }
        busy = true
        defer { busy = false }
        do {
            file = BackupFile(data: try await model.vault.backup(password: password))
        } catch {
            saveError = error.localizedDescription
        }
    }

    private func open() async {
        guard let chosen else { return }
        busy = true
        defer { busy = false }
        do {
            plan = try await model.vault.planRestore(password: restorePassword, file: chosen)
            restoreError = nil
        } catch {
            restoreError = error.localizedDescription
        }
    }

    private func restore(_ p: Backup.Plan) async {
        busy = true
        defer { busy = false }
        if let n = await model.restoreBackup(p) {
            restoreMessage = "Restored \(n) item\(n == 1 ? "" : "s")."
            plan = nil
            chosen = nil
            restorePassword = ""
        } else {
            restoreError = model.error ?? "Restoring failed."
        }
    }
}
