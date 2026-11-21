import StoriiCore
import SwiftUI

/// Weak and reused passwords, and (when asked) the ones Have I Been Pwned has seen in breaches.
struct HealthView: View {
    @Environment(AppModel.self) private var model
    /// id → times seen, once checked.
    @State private var breached: [String: Int]?
    @State private var checking = false
    @State private var error: String?

    var body: some View {
        let report = PasswordHealth.check(model.items)
        let found = (breached ?? [:]).sorted { $0.value > $1.value }
        List {
            if !found.isEmpty {
                Section("Found in data breaches — change these first") {
                    ForEach(found, id: \.key) { id, n in row(id, note: "Seen \(n.formatted()) times") }
                }
            }
            if !report.reused.isEmpty {
                Section("Reused passwords") {
                    ForEach(Array(report.reused.enumerated()), id: \.offset) { i, g in
                        if i > 0 { Divider() }
                        ForEach(g, id: \.self) { row($0) }
                    }
                }
            }
            if !report.weak.isEmpty {
                Section("Weak passwords") { ForEach(report.weak, id: \.self) { row($0) } }
            }
            if found.isEmpty && report.reused.isEmpty && report.weak.isEmpty {
                Text("No reused or weak passwords.").foregroundStyle(.secondary)
            }
            Section {
                Button(checking ? "Checking…" : breached == nil ? "Check for data breaches"
                       : found.isEmpty ? "None found in breaches · check again" : "Check again") {
                    Task { await check() }
                }
                .disabled(checking)
                if let error { Text(error).foregroundStyle(.red) }
            } footer: {
                Text("Asks Have I Been Pwned. Only the first 5 characters of each password’s SHA-1 hash are sent, so neither "
                     + "they nor anyone watching can tell which password was checked.")
            }
        }
        .navigationTitle("Password health")
    }

    private func row(_ id: String, note: String? = nil) -> some View {
        NavigationLink { DetailView(id: id) } label: {
            if let it = model.items[id] {
                VStack(alignment: .leading, spacing: 2) {
                    Text(it.name).font(.body.weight(.medium)).lineLimit(1)
                    let sub = note ?? it.field("username")
                    if !sub.isEmpty { Text(sub).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                }
            }
        }
    }

    private func check() async {
        checking = true
        error = nil
        defer { checking = false }
        do {
            let pws = PasswordHealth.passwords(model.items)
            let seen = try await PasswordHealth.pwned(pws.values)
            breached = pws.compactMapValues { seen[$0] }
        } catch {
            self.error = error.localizedDescription
        }
    }
}
