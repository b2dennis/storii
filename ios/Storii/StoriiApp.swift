import StoriiCore
import SwiftUI

@main
struct StoriiApp: App {
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var phase

    var body: some Scene {
        #if os(iOS)
        WindowGroup {
            RootView()
                .environment(model)
                // Hide secrets in the app switcher.
                .overlay { if phase != .active { Rectangle().fill(.background).overlay(Logo()).ignoresSafeArea() } }
        }
        .onChange(of: phase) { _, p in
            switch p {
            case .background: model.enteredBackground()
            case .active: model.becameActive()
            default: break
            }
        }
        #else
        Window("storii", id: "main") {
            RootView()
                .environment(model)
                .frame(minWidth: 720, minHeight: 480)
                .modifier(MacLifecycle(model: model))
        }
        .defaultSize(width: 960, height: 640)
        .commands { StoriiCommands(model: model) }
        MenuBarExtra("storii", systemImage: "key.horizontal.fill") {
            QuickSearchView().environment(model)
        }
        .menuBarExtraStyle(.window)
        #endif
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Group {
            switch model.status {
            case .notSetUp: SetupView()
            case .locked(let username, let server, let expired):
                if expired { SetupView(server: server, username: username, expired: true) } else { UnlockView() }
            case .unlocked: MainView()
            }
        }
        #if DEBUG
        .task {
            // Debug builds only, for screenshots: `-storii-unlock PASSWORD` unlocks the vault file at launch.
            if case .locked = model.status, let pw = UserDefaults.standard.string(forKey: "storii-unlock") {
                await model.unlock(password: pw)
            }
        }
        #endif
    }
}

struct MainView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        TabView {
            Tab("Secrets", systemImage: "key.horizontal") { SecretsView() }
            Tab("Contexts", systemImage: "globe") { ContextsView() }
            Tab("Settings", systemImage: "gearshape") { SettingsView() }
        }
        .tabViewStyle(.sidebarAdaptable) // a sidebar on the Mac and iPad, tabs on the iPhone
        .task { await model.sync() }
    }
}
