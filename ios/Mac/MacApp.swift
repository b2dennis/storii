#if os(macOS)
import AppKit
import StoriiCore
import SwiftUI

/// Locks after the timeout while storii isn't the active app, and right away when the screen locks or the Mac sleeps.
struct MacLifecycle: ViewModifier {
    let model: AppModel

    func body(content: Content) -> some View {
        content
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in
                model.enteredBackground()
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
                model.becameActive()
            }
            .onReceive(DistributedNotificationCenter.default().publisher(for: .init("com.apple.screenIsLocked"))) { _ in
                model.lock()
            }
            .onReceive(NSWorkspace.shared.notificationCenter.publisher(for: NSWorkspace.willSleepNotification)) { _ in
                model.lock()
            }
    }
}

struct StoriiCommands: Commands {
    let model: AppModel

    var body: some Commands {
        CommandGroup(after: .appSettings) {
            Button("Lock storii") { model.lock() }
                .keyboardShortcut("l", modifiers: [.command, .control])
                .disabled(!model.isUnlocked)
            Button("Sync now") { Task { await model.sync() } }
                .keyboardShortcut("r")
                .disabled(!model.isUnlocked)
        }
    }
}

/// The menu bar search: find a secret and copy it without opening the main window.
struct QuickSearchView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @State private var query = ""
    @State private var copied: String?
    @FocusState private var focused: Bool

    var body: some View {
        Group {
            switch model.status {
            case .notSetUp:
                VStack(spacing: 12) {
                    Logo()
                    Text("Log in to storii in the main window.").foregroundStyle(.secondary)
                    Button("Open storii") { open() }
                }
                .padding(24)
            case .locked(_, _, let expired):
                if expired {
                    VStack(spacing: 12) {
                        Text("The session ended.").foregroundStyle(.secondary)
                        Button("Log in again") { open() }
                    }
                    .padding(24)
                } else {
                    UnlockView(autoBiometrics: false)
                }
            case .unlocked:
                search
            }
        }
        .frame(width: 380)
    }

    private var search: some View {
        let results = Array(model.vault.search(query, types: nil).prefix(30))
        return VStack(spacing: 0) {
            TextField("Search secrets", text: $query)
                .textFieldStyle(.plain)
                .font(.title3)
                .padding(12)
                .focused($focused)
                .onSubmit { if let first = results.first { copy(first, username: false) } }
            Divider()
            if results.isEmpty {
                Text(query.isEmpty ? "No secrets yet." : "No matches").foregroundStyle(.secondary).padding(20)
            } else {
                ScrollView {
                    LazyVStack(spacing: 2) {
                        ForEach(results) { e in row(e) }
                    }
                    .padding(6)
                }
                .frame(maxHeight: 360)
            }
            Divider()
            HStack {
                Text(copied.map { "Copied \($0). It's cleared in a minute." } ?? "Click to copy · ⌥-click copies the username")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Spacer()
                Button { model.lock() } label: { Image(systemName: "lock") }
                    .buttonStyle(.borderless).help("Lock")
                Button { open() } label: { Image(systemName: "macwindow") }
                    .buttonStyle(.borderless).help("Open storii")
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
        }
        .onAppear { focused = true; copied = nil }
    }

    private func row(_ e: Entry) -> some View {
        Button {
            copy(e, username: NSEvent.modifierFlags.contains(.option))
        } label: {
            HStack(spacing: 10) {
                TypeIcon(type: e.item.type)
                VStack(alignment: .leading, spacing: 1) {
                    Text(e.item.name).lineLimit(1)
                    let sub = username(e.item)
                    if !sub.isEmpty { Text(sub).font(.caption).foregroundStyle(.secondary).lineLimit(1) }
                }
                Spacer()
                if e.item.type == Item.totp { TOTPCode(fields: e.item.fields) }
            }
            .contentShape(.rect)
            .padding(.horizontal, 6).padding(.vertical, 4)
        }
        .buttonStyle(.plain)
    }

    private func username(_ it: Item) -> String {
        switch it.type {
        case Item.password: it.field("username")
        case Item.totp: it.field("account")
        case Item.apiKey: it.field("key_id")
        default: ""
        }
    }

    private func copy(_ e: Entry, username wantsUser: Bool) {
        if wantsUser {
            let u = username(e.item)
            guard !u.isEmpty else { return }
            copySecret(u)
            copied = "the username"
        } else {
            copySecret((try? e.item.secretValue()) ?? "")
            copied = e.item.type == Item.totp ? "the code" : "\(e.item.name)"
        }
    }

    private func open() {
        openWindow(id: "main")
        NSApp.activate()
    }
}
#endif
