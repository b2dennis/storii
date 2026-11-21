import StoriiCore
import SwiftUI

/// Recently deleted secrets and contexts: restore them, or forget them for good.
struct TrashView: View {
    @Environment(AppModel.self) private var model
    @State private var items: [Vault.Deleted]?
    @State private var days = 30
    @State private var error: String?
    @State private var busy = false
    @State private var confirmEmpty = false

    var body: some View {
        List {
            if let error { Text(error).foregroundStyle(.red) }
            if let items {
                if items.isEmpty {
                    Text("Nothing deleted recently.").foregroundStyle(.secondary)
                }
                ForEach(items) { d in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(d.item.name).fontWeight(.semibold).lineLimit(1)
                            Text("\(d.item.isContext ? "Context" : typeLabel(d.item.type)) · deleted \(d.deletedAt?.formatted(date: .abbreviated, time: .shortened) ?? "")")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button("Restore") { Task { await restore(d) } }.disabled(busy)
                    }
                }
            } else {
                ProgressView()
            }
            Section {} footer: { Text("Deleted secrets and contexts are kept for \(days) days.") }
        }
        .navigationTitle("Recently deleted")
        .toolbar {
            if !(items ?? []).isEmpty {
                Button("Empty", role: .destructive) { confirmEmpty = true }.disabled(busy)
            }
        }
        .confirmationDialog("Empty the trash?", isPresented: $confirmEmpty, titleVisibility: .visible) {
            Button("Empty", role: .destructive) { Task { await empty() } }
        } message: { Text("\(items?.count ?? 0) deleted item(s) will be gone for good, on every device.") }
        .task { await load() }
        .refreshable { await load() }
    }

    private func load() async {
        do {
            let t = try await model.vault.trash()
            items = t.items
            days = t.days
            error = nil
        } catch {
            self.error = error.localizedDescription
        }
    }

    private func restore(_ d: Vault.Deleted) async {
        busy = true
        if await model.restore([d]) { items?.removeAll { $0.id == d.id } }
        busy = false
    }

    private func empty() async {
        busy = true
        do {
            try await model.vault.emptyTrash()
            items = []
        } catch {
            self.error = error.localizedDescription
        }
        busy = false
    }
}
