#if os(iOS)
import AuthenticationServices
import StoriiCore
import SwiftUI

/// Import from another app (iOS 26 credential exchange): in the other password manager the user picks Export and then
/// storii; iOS opens storii with an ASCredentialExchangeActivity holding a short-lived token, and
/// ASCredentialImportManager hands over what was exported. That's encoded as CXF JSON (Apple's Codable encoding is
/// the CXF format) and read by StoriiCore's CxfImport, the same as on Android. The AutoFill extension declares
/// SupportsCredentialExchange in its Info.plist (project.yml), which is what lists storii as a destination.
enum CredentialExchange {
    /// ASCredentialExchangeActivity, which needs iOS 26 to name.
    static var activityType: String {
        if #available(iOS 26.0, *) { ASCredentialExchangeActivity } else { "ASCredentialExchangeActivity" }
    }

    static func token(_ activity: NSUserActivity) -> UUID? {
        guard #available(iOS 26.0, *) else { return nil }
        return activity.userInfo?[ASCredentialImportToken] as? UUID
    }

    /// What the other app exported, as CXF JSON.
    static func receive(_ token: UUID) async throws -> Data {
        guard #available(iOS 26.0, *) else { throw StoriiError("Importing from another app needs iOS 26.") }
        let exported = try await ASCredentialImportManager().importCredentials(token: token)
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .secondsSince1970
        return try enc.encode(exported)
    }
}

/// The token waits here until the vault is unlocked; then CredentialImportView takes it.
@MainActor @Observable
final class PendingImport {
    var token: UUID?
}

/// What arrived from the other app, what storii will do with it, and the button that does it.
struct CredentialImportView: View {
    let token: UUID
    let done: () -> Void
    @Environment(AppModel.self) private var model
    @State private var plan: Import.Plan?
    @State private var parsed: Import.Parsed?
    @State private var failure: String?
    @State private var imported: Int?

    private var adds: Int { plan?.count(.add) ?? 0 }
    private var usernames: Int { plan?.count(.username) ?? 0 }

    var body: some View {
        NavigationStack {
            Form {
                if let n = imported {
                    Section {
                        Label("Imported \(n == 1 ? "1 item" : "\(n) items").", systemImage: "checkmark.circle.fill")
                    }
                } else if let failure {
                    Section { Text(failure).foregroundStyle(.red) }
                } else if let plan, let parsed {
                    summary(plan, parsed)
                } else {
                    Section { HStack(spacing: 12) { ProgressView(); Text("Receiving from the other app…").foregroundStyle(.secondary) } }
                }
            }
            .navigationTitle("Import")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: imported == nil ? .cancellationAction : .confirmationAction) {
                    Button(imported == nil ? "Cancel" : "Done", action: done).disabled(model.busy)
                }
            }
        }
        .interactiveDismissDisabled(model.busy)
        .task { await receive() }
    }

    @ViewBuilder
    private func summary(_ plan: Import.Plan, _ parsed: Import.Parsed) -> some View {
        Section {
            if adds > 0 { LabeledContent("New", value: "\(adds)") }
            if usernames > 0 { LabeledContent("Usernames filled in", value: "\(usernames)") }
            if plan.count(.skip) > 0 { LabeledContent("Already in storii", value: "\(plan.count(.skip))") }
        } footer: {
            Text(parsed.count == 0 ? "The other app sent nothing storii can import."
                : "\(parsed.count == 1 ? "1 item" : "\(parsed.count) items") from the other app. Importing again later adds nothing twice.")
        }
        let changes = plan.lines.filter { $0.action == .add || $0.action == .username }
        if !changes.isEmpty {
            Section("To import") {
                ForEach(Array(changes.enumerated()), id: \.offset) { _, line in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(line.name)
                        let detail = [line.site, line.action == .username ? "adds the username" : "",
                                      line.differs ? "another password than the one saved" : ""].filter { !$0.isEmpty }
                        if !detail.isEmpty { Text(detail.joined(separator: " · ")).font(.footnote).foregroundStyle(.secondary) }
                    }
                }
            }
        }
        if !parsed.failed.isEmpty {
            Section("Can't be imported") {
                ForEach(parsed.failed, id: \.self) { Text($0).font(.footnote) }
            }
        }
        if let e = model.error { Section { Text(e).foregroundStyle(.red) } }
        Section {
            Button {
                Task { await save(plan) }
            } label: {
                Group { if model.busy { ProgressView() } else { Text("Import") } }.frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(model.busy || plan.writes.isEmpty)
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets())
        }
    }

    private func receive() async {
        do {
            let data = try await CredentialExchange.receive(token)
            let p = try CxfImport.parse(data)
            parsed = p
            plan = Import.build(existing: model.items, p, newId: { UUID().uuidString.lowercased() })
        } catch {
            failure = "storii couldn't receive the items from the other app. Export them again. (\(error.localizedDescription))"
        }
    }

    private func save(_ plan: Import.Plan) async {
        // Built again against the vault as it is now, in case a sync landed since.
        let fresh = parsed.map { Import.build(existing: model.items, $0, newId: { UUID().uuidString.lowercased() }) } ?? plan
        let n = fresh.count(.add) + fresh.count(.username)
        if await model.write(fresh.writes.map { .put(id: $0.id, item: $0.item) }) != nil { imported = n }
    }
}
#endif
