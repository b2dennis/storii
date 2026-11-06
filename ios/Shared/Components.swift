import StoriiCore
import SwiftUI

struct Logo: View {
    var body: some View {
        Image(systemName: "key.horizontal.fill")
            .font(.system(size: 40, weight: .semibold))
            .foregroundStyle(.tint)
            .frame(width: 76, height: 76)
            .background(Color.accentColor.opacity(0.12), in: .rect(cornerRadius: 20))
            .accessibilityHidden(true)
    }
}

struct TypeIcon: View {
    let type: String?
    var context = false

    var symbol: String {
        if context {
            return switch type {
            case "app": "app.badge"
            case "other": "folder"
            default: "globe"
            }
        }
        return switch type {
        case Item.password: "key.fill"
        case Item.totp: "clock.badge.checkmark"
        case Item.apiKey: "chevron.left.forwardslash.chevron.right"
        default: "note.text"
        }
    }

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(.tint)
            .frame(width: 34, height: 34)
            .background(Color.accentColor.opacity(0.12), in: .rect(cornerRadius: 9))
            .accessibilityHidden(true)
    }
}

/// The current code of a 2FA secret with its countdown, updating every second.
struct TOTPCode: View {
    let fields: [String: String]
    var large = false

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            if let t = try? TOTP(fields: fields) {
                let code = t.code(at: ctx.date)
                HStack(spacing: 10) {
                    Text(Self.grouped(code))
                        .font(.system(large ? .largeTitle : .body, design: .monospaced).weight(.semibold))
                        .contentTransition(.numericText())
                    Gauge(value: Double(t.remaining(at: ctx.date)), in: 0...Double(t.period)) { EmptyView() }
                        .gaugeStyle(.accessoryCircularCapacity)
                        .scaleEffect(large ? 0.6 : 0.4)
                        .frame(width: large ? 40 : 26, height: large ? 40 : 26)
                        .tint(t.remaining(at: ctx.date) <= 5 ? .red : .accentColor)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Code \(code), \(t.remaining(at: ctx.date)) seconds left")
            } else {
                Text("Invalid 2FA secret").foregroundStyle(.red)
            }
        }
    }

    static func grouped(_ code: String) -> String {
        guard code.count == 6 || code.count == 8 else { return code }
        let half = code.count / 2
        return String(code.prefix(half)) + " " + String(code.suffix(half))
    }
}

/// Master password entry, plus Face ID when turned on.
struct UnlockView: View {
    @Environment(AppModel.self) private var model
    @State private var password = ""
    @FocusState private var focused: Bool
    var title = "storii is locked"
    var autoBiometrics = true

    var body: some View {
        VStack(spacing: 18) {
            Spacer()
            Logo()
            Text(title).font(.title2.bold())
            Text("\(model.username) · \(model.server)").font(.footnote).foregroundStyle(.secondary)
            SecureField("Master password", text: $password)
                .passwordContent()
                .textFieldStyle(.plain)
                .focused($focused)
                .submitLabel(.go)
                .onSubmit(unlock)
                .padding(12)
                .background(Color.fieldBackground, in: .rect(cornerRadius: 10))
            Button(action: unlock) {
                if model.busy { ProgressView().frame(maxWidth: .infinity) } else { Text("Unlock").frame(maxWidth: .infinity) }
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(password.isEmpty || model.busy)
            if Biometrics.enabled {
                Button {
                    Task { await model.unlockWithBiometrics() }
                } label: {
                    Label("Unlock with \(Biometrics.name)", systemImage: Platform.biometricsSymbol)
                }
            }
            if let e = model.error { Text(e).foregroundStyle(.red).font(.callout).multilineTextAlignment(.center) }
            Spacer()
            Spacer()
        }
        .padding(24)
        .frame(maxWidth: 480)
        .task {
            if autoBiometrics && Biometrics.enabled {
                let ok = await model.unlockWithBiometrics()
                if !ok { focused = true }
            } else {
                focused = true
            }
        }
    }

    private func unlock() {
        guard !password.isEmpty else { return }
        Task {
            if await model.unlock(password: password) { password = "" }
        }
    }
}
