import StoriiCore
import SwiftUI

struct ContextsView: View {
    @Environment(AppModel.self) private var model
    @State private var adding = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    ForEach(model.contexts) { c in
                        NavigationLink(value: c.id) {
                            HStack(spacing: 12) {
                                TypeIcon(type: c.item.contextType, context: true)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(c.item.name).font(.body.weight(.medium))
                                    Text((c.item.urls + c.item.androidPackages).joined(separator: ", ").nilIfEmpty ?? "No websites or apps")
                                        .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                                }
                                Spacer()
                                Text("\(model.secrets.filter { $0.item.contexts.contains(c.id) }.count)").foregroundStyle(.secondary)
                            }
                        }
                    }
                } footer: {
                    Text("A context is a website or app. Its secrets are offered by AutoFill there, and one secret can belong to several contexts.")
                }
            }
            .navigationTitle("Contexts")
            .navigationDestination(for: String.self) { ContextEditView(id: $0) }
            .toolbar { Button { adding = true } label: { Label("Add", systemImage: "plus") } }
            .sheet(isPresented: $adding) { NavigationStack { ContextEditView(id: nil) }.sheetSize(height: 460) }
        }
    }
}

struct ContextEditView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let id: String?
    @State private var item = Item.context("")
    @State private var urls = ""
    @State private var loaded = false
    @State private var confirmDelete = false

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $item.name)
                Picker("Kind", selection: Binding(get: { item.contextType ?? "website" }, set: { item.contextType = $0 })) {
                    Text("Website").tag("website")
                    Text("App").tag("app")
                    Text("Other").tag("other")
                }
                .pickerStyle(.segmented)
            }
            Section {
                TextField("https://example.com", text: $urls, axis: .vertical)
                    .lineLimit(2...)
                    .urlInput()
            } header: { Text("Websites, one per line") } footer: {
                Text("Subdomains match too. iOS apps are matched through the websites they belong to.")
            }
            if !item.androidPackages.isEmpty {
                Section("Android apps") { ForEach(item.androidPackages, id: \.self) { Text($0).monospaced() } }
            }
            if let id {
                let linked = model.secrets.filter { $0.item.contexts.contains(id) }
                if !linked.isEmpty {
                    Section("Secrets") {
                        ForEach(linked) { e in Label(e.item.name, systemImage: TypeIcon(type: e.item.type).symbol) }
                    }
                }
                Section { Button("Delete context", role: .destructive) { confirmDelete = true } } footer: {
                    Text("Its secrets are kept; they just aren't linked to it any more.")
                }
            }
            if let e = model.error { Text(e).foregroundStyle(.red) }
        }
        .formStyle(.grouped)
        .navigationTitle(id == nil ? "New context" : item.name)
        .inlineTitle()
        .toolbar {
            if id == nil { ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } } }
            ToolbarItem(placement: .confirmationAction) { Button("Save", action: save).disabled(model.busy) }
        }
        .confirmationDialog("Delete \(item.name)?", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("Delete", role: .destructive) { Task { if await model.delete([id!]) { dismiss() } } }
        }
        .onAppear {
            guard !loaded else { return }
            loaded = true
            if let id, let it = model.items[id] {
                item = it
                urls = it.urls.joined(separator: "\n")
            }
        }
    }

    private func save() {
        item.urls = urls.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        if item.name.trimmingCharacters(in: .whitespaces).isEmpty, let first = item.urls.first { item.name = Match.host(first) }
        Task { if await model.put(id, item) != nil { dismiss() } }
    }
}

extension String {
    var nilIfEmpty: String? { isEmpty ? nil : self }
}
