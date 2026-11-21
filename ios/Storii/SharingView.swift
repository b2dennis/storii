import StoriiCore
import SwiftUI

/// Shares: create them, add people after comparing their key fingerprint, move secrets in and out.
struct SharingView: View {
    @Environment(AppModel.self) private var model
    @State private var newName = ""
    @State private var error: String?

    var body: some View {
        List {
            Section {
                let fp = model.vault.fingerprint
                Text(fp.isEmpty ? "Not set up yet: sync once, or the server may be too old." : fp)
                    .font(.body.monospaced()).textSelection(.enabled)
            } header: { Text("Your fingerprint") } footer: {
                Text("When someone adds you to a share, they should see this too. Compare it in person or over a call.")
            }
            if let error { Text(error).foregroundStyle(.red) }
            Section("New share") {
                HStack {
                    TextField("Name, e.g. Family", text: $newName)
                    Button("Create") { Task { await create() } }
                        .disabled(newName.trimmingCharacters(in: .whitespaces).isEmpty || model.busy)
                }
            }
            if model.shares.isEmpty {
                Text("No shares yet.").foregroundStyle(.secondary)
            }
            ForEach(model.shares) { s in
                NavigationLink { ShareDetailView(shareID: s.id) } label: {
                    VStack(alignment: .leading) {
                        Text(s.name.isEmpty ? "Unnamed share" : s.name).fontWeight(.semibold)
                        Text("\(count(s.id)) secret(s) · \(s.members.map(\.username).joined(separator: ", "))")
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
            }
        }
        .navigationTitle("Sharing")
        .refreshable { await model.sync() }
    }

    private func count(_ sid: String) -> Int { model.secrets.filter { model.shareOf($0.id)?.id == sid }.count }

    private func create() async {
        let n = newName
        if await model.run({ try await model.vault.createShare(name: n) }) {
            newName = ""
            error = nil
        } else {
            error = model.error
        }
    }
}

struct ShareDetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let shareID: String
    @State private var adding = ""
    @State private var found: (username: String, publicKey: String, fingerprint: String)?
    @State private var picking = false
    @State private var renaming: String?
    @State private var confirmDelete = false
    @State private var error: String?

    private var share: Share? { model.shares.first { $0.id == shareID } }

    var body: some View {
        if let s = share {
            List {
                if let error { Text(error).foregroundStyle(.red) }
                Section("Secrets") {
                    let inside = model.secrets.filter { model.shareOf($0.id)?.id == shareID }
                    if inside.isEmpty { Text("Nothing shared yet.").foregroundStyle(.secondary) }
                    ForEach(inside) { e in
                        HStack {
                            Text(e.item.name).lineLimit(1)
                            Spacer()
                            Button("Move to my vault") { Task { await move([e.id], to: "") } }
                                .buttonStyle(.borderless).font(.caption)
                        }
                    }
                    Button("Add secrets…", systemImage: "plus") { picking = true }
                }
                Section {
                    ForEach(s.members, id: \.username) { m in
                        HStack {
                            Text(m.username)
                            if m.owner { Text("owner").font(.caption).foregroundStyle(.secondary) }
                            Spacer()
                            if s.mine && !m.owner {
                                Button("Remove", role: .destructive) {
                                    Task { await act { try await model.vault.removeMember(shareID, username: m.username) } }
                                }.buttonStyle(.borderless).font(.caption)
                            }
                        }
                    }
                    if s.mine {
                        if let f = found {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Does \(f.username) see this fingerprint in storii → Settings → Shares?")
                                Text(f.fingerprint).font(.body.monospaced())
                                HStack {
                                    Button("It matches, add") {
                                        Task {
                                            if await act({ try await model.vault.addMember(shareID, username: f.username, publicKey: f.publicKey) }) {
                                                found = nil
                                                adding = ""
                                            }
                                        }
                                    }
                                    Button("Cancel", role: .cancel) { found = nil }
                                }.buttonStyle(.borderless)
                            }
                        } else {
                            HStack {
                                TextField("Username", text: $adding).plainInput()
                                Button("Add") {
                                    Task {
                                        let u = adding
                                        await act { found = try await model.vault.memberKey(u) }
                                    }
                                }.disabled(adding.trimmingCharacters(in: .whitespaces).isEmpty)
                            }
                        }
                    }
                } header: { Text("People") } footer: {
                    Text(s.mine ? "Removed people keep anything they copied before."
                         : "Shared by \(s.owner). Leaving removes its secrets from your devices.")
                }
                Section {
                    if s.mine {
                        Button("Rename") { renaming = s.name }
                        Button("Delete share", role: .destructive) { confirmDelete = true }
                    } else {
                        Button("Leave share", role: .destructive) { confirmDelete = true }
                    }
                }
            }
            .navigationTitle(s.name.isEmpty ? "Share" : s.name)
            .sheet(isPresented: $picking) { PickSecretsView(shareID: shareID) { ids in Task { await move(ids, to: shareID) } } }
            .alert("Rename share", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
                TextField("Name", text: Binding(get: { renaming ?? "" }, set: { renaming = $0 }))
                Button("Save") {
                    let n = renaming ?? ""
                    Task { await act { try await model.vault.renameShare(shareID, name: n) } }
                }
                Button("Cancel", role: .cancel) {}
            }
            .confirmationDialog(s.mine ? "Delete \(s.name)?" : "Leave \(s.name)?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button(s.mine ? "Delete" : "Leave", role: .destructive) {
                    Task { if await act({ try await model.vault.deleteShare(shareID) }) { dismiss() } }
                }
            } message: {
                Text(s.mine ? "Its secrets are deleted for everyone in it. Move the ones you want to keep to your vault first."
                     : "Its secrets disappear from your devices.")
            }
        } else {
            ContentUnavailableView("Share gone", systemImage: "person.2.slash")
        }
    }

    @discardableResult
    private func act(_ f: () async throws -> Void) async -> Bool {
        let ok = await model.run(f)
        error = ok ? nil : model.error
        return ok
    }

    private func move(_ ids: [String], to sid: String) async {
        let ok = await model.move(ids, to: sid)
        error = ok ? nil : model.error
    }
}

/// Picks personal (or other shares') secrets to move into a share.
struct PickSecretsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let shareID: String
    let done: ([String]) -> Void
    @State private var picked: Set<String> = []

    var body: some View {
        NavigationStack {
            List(model.secrets.filter { model.shareOf($0.id)?.id != shareID }) { e in
                Button {
                    if picked.contains(e.id) { picked.remove(e.id) } else { picked.insert(e.id) }
                } label: {
                    HStack {
                        VStack(alignment: .leading) {
                            Text(e.item.name).foregroundStyle(.primary)
                            if let s = model.shareOf(e.id) { Text("in \(s.name)").font(.caption).foregroundStyle(.secondary) }
                        }
                        Spacer()
                        if picked.contains(e.id) { Image(systemName: "checkmark").foregroundStyle(.tint) }
                    }
                }
            }
            .navigationTitle("Add secrets")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Move \(picked.count)") {
                        done(Array(picked))
                        dismiss()
                    }.disabled(picked.isEmpty)
                }
            }
        }
    }
}

/// On a secret's page: which share it's in, and a menu to move it.
struct ShareLine: View {
    @Environment(AppModel.self) private var model
    let id: String

    var body: some View {
        Section {
            let current = model.shareOf(id)
            HStack {
                Label(current.map { "Shared in \($0.name)" } ?? "In your vault only",
                      systemImage: current == nil ? "lock" : "person.2")
                Spacer()
                if !model.shares.isEmpty || current != nil {
                    Menu("Move…") {
                        if current != nil { Button("My vault") { Task { await model.move([id], to: "") } } }
                        ForEach(model.shares.filter { $0.id != current?.id }) { s in
                            Button(s.name) { Task { await model.move([id], to: s.id) } }
                        }
                    }
                }
            }
        } header: { Text("Sharing") }
    }
}
