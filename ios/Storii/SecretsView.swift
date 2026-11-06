import StoriiCore
import SwiftUI

struct SecretsView: View {
    @Environment(AppModel.self) private var model
    @State private var query = ""
    @State private var filter: String?
    @State private var adding = false

    var body: some View {
        NavigationStack {
            let entries = model.vault.search(query, types: filter.map { [$0] })
            List {
                ForEach(entries) { e in
                    NavigationLink(value: e.id) { SecretRow(entry: e) }
                        .swipeActions(edge: .leading) {
                            Button {
                                copySecret((try? e.item.secretValue()) ?? "")
                            } label: { Label("Copy", systemImage: "doc.on.doc") }
                                .tint(.accentColor)
                        }
                }
            }
            .overlay {
                if entries.isEmpty {
                    if model.secrets.isEmpty {
                        ContentUnavailableView {
                            Label("No secrets yet", systemImage: "key.horizontal")
                        } description: {
                            Text("Add a password, a 2FA code, an API key or a note.")
                        } actions: {
                            Button("Add a secret") { adding = true }.buttonStyle(.borderedProminent)
                        }
                    } else {
                        ContentUnavailableView.search(text: query)
                    }
                }
            }
            .searchable(text: $query, prompt: "Search names, users, sites")
            .refreshable { await model.sync() }
            .navigationTitle("Secrets")
            .navigationDestination(for: String.self) { DetailView(id: $0) }
            .toolbar {
                ToolbarItem(placement: .navigation) {
                    Menu {
                        Picker("Type", selection: $filter) {
                            Text("All").tag(String?.none)
                            ForEach(Item.types, id: \.self) { Text(typeLabel($0)).tag(String?.some($0)) }
                        }
                    } label: {
                        Label("Filter", systemImage: filter == nil ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
                    }
                }
                ToolbarItem(placement: .primaryAction) {
                    Button { adding = true } label: { Label("Add", systemImage: "plus") }
                }
            }
            .sheet(isPresented: $adding) { EditView(id: nil).sheetSize() }
        }
    }
}

struct SecretRow: View {
    @Environment(AppModel.self) private var model
    let entry: Entry

    var subtitle: String {
        let it = entry.item
        let who = switch it.type {
        case Item.password: it.field("username")
        case Item.totp: [it.field("issuer"), it.field("account")].filter { !$0.isEmpty }.joined(separator: " · ")
        case Item.apiKey: it.field("key_id")
        default: ""
        }
        let ctx = it.contexts.compactMap { model.items[$0]?.name }.joined(separator: ", ")
        return [who, ctx].filter { !$0.isEmpty }.joined(separator: " — ")
    }

    var body: some View {
        HStack(spacing: 12) {
            TypeIcon(type: entry.item.type)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.item.name).font(.body.weight(.medium)).lineLimit(1)
                if !subtitle.isEmpty { Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
            }
            Spacer()
            if entry.item.type == Item.totp { TOTPCode(fields: entry.item.fields) }
        }
    }
}

/// One field with copy and, for secret values, reveal.
struct FieldRow: View {
    let label: String
    let value: String
    var secret = false
    var mono = false
    @State private var shown = false
    @State private var copied = false

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 3) {
                Text(label).font(.caption).foregroundStyle(.secondary)
                Text(secret && !shown ? String(repeating: "•", count: min(max(value.count, 8), 16)) : value)
                    .font(mono || (secret && shown) ? .body.monospaced() : .body)
                    .textSelection(.enabled)
            }
            Spacer()
            if secret {
                Button { shown.toggle() } label: { Image(systemName: shown ? "eye.slash" : "eye") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(shown ? "Hide" : "Show")
            }
            Button {
                copySecret(value)
                copied = true
                Task { try? await Task.sleep(for: .seconds(1.5)); copied = false }
            } label: { Image(systemName: copied ? "checkmark" : "doc.on.doc") }
                .buttonStyle(.borderless)
                .accessibilityLabel("Copy \(label)")
        }
    }
}

struct DetailView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let id: String
    @State private var editing = false
    @State private var confirmDelete = false

    var body: some View {
        if let it = model.items[id] {
            List {
                Section {
                    HStack(spacing: 12) {
                        TypeIcon(type: it.type)
                        VStack(alignment: .leading) {
                            Text(it.name).font(.title3.bold())
                            Text(typeLabel(it.type)).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                Section {
                    switch it.type {
                    case Item.password:
                        if !it.field("username").isEmpty { FieldRow(label: "Username", value: it.field("username")) }
                        FieldRow(label: "Password", value: it.field("password"), secret: true)
                    case Item.totp:
                        HStack {
                            TOTPCode(fields: it.fields, large: true)
                            Spacer()
                            Button {
                                copySecret((try? it.secretValue()) ?? "")
                            } label: { Image(systemName: "doc.on.doc") }
                                .buttonStyle(.borderless)
                                .accessibilityLabel("Copy code")
                        }
                        if !it.field("issuer").isEmpty { FieldRow(label: "Issuer", value: it.field("issuer")) }
                        if !it.field("account").isEmpty { FieldRow(label: "Account", value: it.field("account")) }
                        FieldRow(label: "Setup key", value: it.field("secret"), secret: true, mono: true)
                    case Item.apiKey:
                        if !it.field("key_id").isEmpty { FieldRow(label: "Key ID", value: it.field("key_id"), mono: true) }
                        FieldRow(label: "Key", value: it.field("key"), secret: true, mono: true)
                    default:
                        EmptyView()
                    }
                    let known: Set<String> = ["username", "password", "secret", "issuer", "account", "algorithm", "digits", "period", "key", "key_id"]
                    ForEach(it.fields.keys.filter { !known.contains($0) }.sorted(), id: \.self) { k in
                        FieldRow(label: k, value: it.fields[k] ?? "")
                    }
                    ForEach(Array(it.custom.enumerated()), id: \.offset) { _, f in
                        FieldRow(label: f.name, value: f.value, secret: f.hidden)
                    }
                }
                if let n = it.notes, !n.isEmpty {
                    Section("Notes") { Text(n).textSelection(.enabled) }
                }
                Section {
                    if it.contexts.isEmpty {
                        Text("Not in any context, so AutoFill only finds it by searching.").foregroundStyle(.secondary)
                    }
                    ForEach(it.contexts, id: \.self) { cid in
                        if let c = model.items[cid] {
                            Label {
                                VStack(alignment: .leading) {
                                    Text(c.name)
                                    if !c.urls.isEmpty { Text(c.urls.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary) }
                                }
                            } icon: { Image(systemName: TypeIcon(type: c.contextType, context: true).symbol) }
                        }
                    }
                } header: { Text("Contexts") }
                Section {
                    Button("Delete", role: .destructive) { confirmDelete = true }
                } footer: {
                    if let u = it.updatedAt { Text("Changed \(u)") }
                }
            }
            .inlineTitle()
            .toolbar { Button("Edit") { editing = true } }
            .sheet(isPresented: $editing) { EditView(id: id).sheetSize() }
            .confirmationDialog("Delete \(it.name)?", isPresented: $confirmDelete, titleVisibility: .visible) {
                Button("Delete", role: .destructive) {
                    Task { if await model.delete([id]) { dismiss() } }
                }
            }
        } else {
            ContentUnavailableView("Deleted", systemImage: "trash")
        }
    }
}
