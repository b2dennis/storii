import CoreImage
import StoriiCore
import SwiftUI
import UniformTypeIdentifiers
#if os(iOS)
import VisionKit
#endif

/// Add or edit a secret: its type's fields, the contexts it belongs to, custom fields and notes.
struct EditView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    let id: String?

    @State private var item = Item.secret(Item.password, name: "")
    @State private var loaded = false
    @State private var showAdvanced = false
    @State private var scanning = false
    @State private var choosingImage = false
    @State private var newContext: String?
    @State private var genLength = 20.0
    @State private var genSymbols = true
    @State private var localError: String?

    private func binding(_ key: String) -> Binding<String> {
        Binding(get: { item.fields[key] ?? "" }, set: { item.fields[key] = $0.isEmpty ? nil : $0 })
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $item.name)
                    if id == nil {
                        Picker("Type", selection: Binding(get: { item.type ?? Item.password }, set: { item.type = $0 })) {
                            ForEach(Item.types, id: \.self) { Text(typeLabel($0)).tag($0) }
                        }
                        .pickerStyle(.segmented)
                    }
                }
                switch item.type {
                case Item.password: passwordFields
                case Item.totp: totpFields
                case Item.apiKey:
                    Section("API key") {
                        TextField("Key ID (optional)", text: binding("key_id")).monospaced().plainInput()
                        TextField("Key", text: binding("key"), axis: .vertical).monospaced().plainInput()
                    }
                case Item.card:
                    Section {
                        TextField("Cardholder", text: binding("cardholder")).plainInput()
                        TextField("Card number", text: binding("number")).monospaced().plainInput()
                        TextField("Expiry (MM/YY)", text: binding("expiry")).monospaced().plainInput()
                        SecureField("CVC", text: binding("cvc"))
                    } header: { Text("Card") } footer: { Text(Card.displayBrand(item.field("number"))) }
                default: EmptyView()
                }
                contextsSection
                Section {
                    ForEach(item.custom.indices, id: \.self) { i in
                        VStack {
                            TextField("Field name", text: $item.custom[i].name).font(.caption)
                            HStack {
                                if item.custom[i].hidden { SecureField("Value", text: $item.custom[i].value) } else { TextField("Value", text: $item.custom[i].value) }
                                Toggle("Hidden", isOn: $item.custom[i].hidden).labelsHidden()
                                #if os(macOS)
                                Button { item.custom.remove(at: i) } label: { Image(systemName: "minus.circle") }
                                    .buttonStyle(.borderless).help("Remove field")
                                #endif
                            }
                        }
                    }
                    .onDelete { item.custom.remove(atOffsets: $0) }
                    Button("Add field", systemImage: "plus") { item.custom.append(CustomField(name: "", value: "")) }
                } header: { Text("Custom fields") } footer: { Text("Switch on to hide a value until it is revealed.") }
                Section(item.type == Item.note ? "Note" : "Notes") {
                    TextField("Notes", text: Binding(get: { item.notes ?? "" }, set: { item.notes = $0.isEmpty ? nil : $0 }), axis: .vertical)
                        .lineLimit((item.type == Item.note ? 6 : 2)...)
                }
                if let e = localError ?? model.error { Text(e).foregroundStyle(.red) }
            }
            .formStyle(.grouped)
            .navigationTitle(id == nil ? "New secret" : "Edit")
            .inlineTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save", action: save).disabled(model.busy)
                }
            }
            #if os(iOS)
            .sheet(isPresented: $scanning) {
                QRScanner { code in
                    scanning = false
                    apply(uri: code)
                }
                .ignoresSafeArea()
            }
            #endif
            .fileImporter(isPresented: $choosingImage, allowedContentTypes: [.image]) { result in
                guard case .success(let url) = result else { return }
                let scoped = url.startAccessingSecurityScopedResource()
                defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                if let image = CIImage(contentsOf: url) { applyQR(image) }
            }
            .alert("New context", isPresented: Binding(get: { newContext != nil }, set: { if !$0 { newContext = nil } })) {
                TextField("Website, e.g. github.com", text: Binding(get: { newContext ?? "" }, set: { newContext = $0 }))
                    .urlInput()
                Button("Add") { addContext() }
                Button("Cancel", role: .cancel) { newContext = nil }
            } message: { Text("Secrets in a context are offered by AutoFill on its website and in its apps.") }
            .onAppear {
                guard !loaded else { return }
                loaded = true
                if let id, let it = model.items[id] { item = it }
                model.error = nil
            }
        }
    }

    private var passwordFields: some View {
        Section {
            TextField("Username or email", text: binding("username"))
                .usernameContent().plainInput()
            HStack {
                TextField("Password", text: binding("password")).monospaced().plainInput()
                Button {
                    item.fields["password"] = StoriiCrypto.generatePassword(length: Int(genLength), symbols: genSymbols)
                } label: { Image(systemName: "dice") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Generate password")
            }
            DisclosureGroup("Generator") {
                Stepper("Length \(Int(genLength))", value: $genLength, in: 8...64)
                Toggle("Symbols", isOn: $genSymbols)
            }
        } header: { Text("Login") }
    }

    private var totpFields: some View {
        Section {
            #if os(iOS)
            if DataScannerViewController.isSupported {
                Button("Scan QR code", systemImage: "qrcode.viewfinder") { scanning = true }
            }
            #endif
            Button("Paste link or QR code image", systemImage: "doc.on.clipboard") { paste() }
            Button("Choose QR code image…", systemImage: "photo") { choosingImage = true }
            TextField("Setup key", text: binding("secret")).monospaced().plainInput()
            TextField("Issuer (optional)", text: binding("issuer"))
            TextField("Account (optional)", text: binding("account")).plainInput()
            DisclosureGroup("Advanced", isExpanded: $showAdvanced) {
                Picker("Algorithm", selection: Binding(get: { item.fields["algorithm"] ?? "SHA1" }, set: { item.fields["algorithm"] = $0 == "SHA1" ? nil : $0 })) {
                    ForEach(["SHA1", "SHA256", "SHA512"], id: \.self) { Text($0) }
                }
                Picker("Digits", selection: Binding(get: { item.fields["digits"] ?? "6" }, set: { item.fields["digits"] = $0 == "6" ? nil : $0 })) {
                    ForEach(["6", "7", "8"], id: \.self) { Text($0) }
                }
                Picker("Period", selection: Binding(get: { item.fields["period"] ?? "30" }, set: { item.fields["period"] = $0 == "30" ? nil : $0 })) {
                    ForEach(["30", "60"], id: \.self) { Text("\($0) s") }
                }
            }
            if !(item.fields["secret"] ?? "").isEmpty, (try? TOTP(fields: item.fields)) != nil {
                LabeledContent("Current code") { TOTPCode(fields: item.fields) }
            }
        } header: { Text("2FA") } footer: {
            Text("The setup key is shown next to the QR code when you turn on two-factor authentication. "
                + "To read the QR code instead, copy a screenshot of it (⌃⇧⌘4 on a Mac) and paste it here.")
        }
    }

    private var contextsSection: some View {
        Section {
            ForEach(model.contexts) { c in
                Button {
                    if let i = item.contexts.firstIndex(of: c.id) { item.contexts.remove(at: i) } else { item.contexts.append(c.id) }
                } label: {
                    HStack {
                        Image(systemName: TypeIcon(type: c.item.contextType, context: true).symbol).frame(width: 24)
                        VStack(alignment: .leading) {
                            Text(c.item.name).foregroundStyle(.primary)
                            if !c.item.urls.isEmpty { Text(c.item.urls.joined(separator: ", ")).font(.caption).foregroundStyle(.secondary) }
                        }
                        Spacer()
                        if item.contexts.contains(c.id) { Image(systemName: "checkmark").foregroundStyle(.tint) }
                    }
                }
            }
            Button("New website context", systemImage: "plus") { newContext = "" }
        } header: { Text("Contexts") } footer: { Text("Where this secret is used. One secret can belong to several.") }
    }

    /// An otpauth:// link, or an image with its QR code, from the clipboard.
    private func paste() {
        if let s = Platform.pasteboardString, s.lowercased().hasPrefix("otpauth://") {
            apply(uri: s)
        } else if let image = Platform.pasteboardImage {
            applyQR(image)
        } else {
            localError = "The clipboard has no otpauth:// link or QR code image."
        }
    }

    private func applyQR(_ image: CIImage) {
        guard let link = otpauthLinks(in: image).first else {
            localError = "No 2FA QR code found in the image."
            return
        }
        apply(uri: link)
    }

    private func apply(uri: String) {
        do {
            let t = try TOTP(uri: uri)
            item.fields = t.fields
            if item.name.isEmpty { item.name = t.issuer.isEmpty ? t.account : t.issuer }
            if !t.issuer.isEmpty, item.contexts.isEmpty,
               let c = model.contexts.first(where: { $0.item.name.localizedCaseInsensitiveContains(t.issuer) }) {
                item.contexts = [c.id]
            }
            localError = nil
        } catch {
            localError = error.localizedDescription
        }
    }

    private func addContext() {
        let host = Match.host(newContext)
        newContext = nil
        guard !host.isEmpty else { return }
        if let c = model.contexts.first(where: { $0.item.matches(host: host) }) {
            if !item.contexts.contains(c.id) { item.contexts.append(c.id) }
            return
        }
        Task {
            if let cid = await model.put(nil, .context(host, urls: ["https://" + host])) { item.contexts.append(cid) }
        }
    }

    private func save() {
        item.name = item.name.trimmingCharacters(in: .whitespaces)
        item.custom.removeAll { $0.name.isEmpty && $0.value.isEmpty }
        if item.type == Item.card {
            guard Card.valid(item.field("number")) else { localError = "That card number isn't valid. Check for a typo."; return }
            item.fields["number"] = Card.digits(item.field("number"))
            if !item.field("expiry").isEmpty {
                let e = Card.normalizeExpiry(item.field("expiry"))
                guard !e.isEmpty else { localError = "Write the expiry as MM/YY."; return }
                item.fields["expiry"] = e
            }
            if item.name.isEmpty {
                item.name = "\(Card.displayBrand(item.field("number")).isEmpty ? "Card" : Card.displayBrand(item.field("number"))) \(Card.digits(item.field("number")).suffix(4))"
            }
        }
        if item.type == Item.totp, var s = item.fields["secret"] {
            s.removeAll { $0 == " " }
            item.fields["secret"] = s.uppercased()
        }
        do {
            try item.validate()
        } catch {
            localError = error.localizedDescription
            return
        }
        localError = nil
        Task { if await model.put(id, item) != nil { dismiss() } }
    }
}

#if os(iOS)
/// Live camera QR scanning with VisionKit.
struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let vc = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])], qualityLevel: .balanced,
                                           isHighlightingEnabled: true)
        vc.delegate = context.coordinator
        // Scanning can only start once the view is on screen.
        DispatchQueue.main.async { try? vc.startScanning() }
        return vc
    }

    func updateUIViewController(_ vc: DataScannerViewController, context: Context) {}

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let onCode: (String) -> Void
        private var done = false
        init(onCode: @escaping (String) -> Void) { self.onCode = onCode }

        func dataScanner(_ scanner: DataScannerViewController, didAdd added: [RecognizedItem], allItems: [RecognizedItem]) {
            for case .barcode(let b) in added {
                if let s = b.payloadStringValue, s.lowercased().hasPrefix("otpauth://"), !done {
                    done = true
                    scanner.stopScanning()
                    onCode(s)
                }
            }
        }
    }
}
#endif
