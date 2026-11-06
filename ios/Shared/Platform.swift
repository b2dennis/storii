import CoreImage
import StoriiCore
import SwiftUI
#if os(iOS)
import UIKit
#else
import AppKit
#endif

// The differences between iOS and macOS, so the views can be shared.

extension Color {
    /// The background of text fields drawn as rounded boxes.
    static var fieldBackground: Color {
        #if os(iOS)
        Color(.secondarySystemBackground)
        #else
        Color(nsColor: .controlBackgroundColor)
        #endif
    }
}

enum Platform {
    @MainActor static var deviceName: String {
        #if os(iOS)
        "storii on \(UIDevice.current.model)"
        #else
        "storii on \(Host.current().localizedName ?? "Mac")"
        #endif
    }

    /// Where AutoFill is switched on, for the settings footer.
    static var autofillSettingsPath: String {
        #if os(iOS)
        "Settings › General › AutoFill & Passwords"
        #else
        "System Settings › General › AutoFill & Passwords"
        #endif
    }

    static var biometricsSymbol: String {
        #if os(iOS)
        "faceid"
        #else
        "touchid"
        #endif
    }

    static var pasteboardString: String? {
        #if os(iOS)
        UIPasteboard.general.string
        #else
        NSPasteboard.general.string(forType: .string)
        #endif
    }

    /// An image on the clipboard (e.g. a screenshot copied with ⌃⇧⌘4), for reading a QR code from it.
    static var pasteboardImage: CIImage? {
        #if os(iOS)
        UIPasteboard.general.image.flatMap { CIImage(image: $0) }
        #else
        NSPasteboard.general.data(forType: .tiff).flatMap { CIImage(data: $0) }
            ?? NSPasteboard.general.data(forType: .png).flatMap { CIImage(data: $0) }
        #endif
    }
}

/// The otpauth:// links in the QR codes of an image.
func otpauthLinks(in image: CIImage) -> [String] {
    let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
    return (detector?.features(in: image) ?? [])
        .compactMap { ($0 as? CIQRCodeFeature)?.messageString }
        .filter { $0.lowercased().hasPrefix("otpauth://") }
}

/// Copies a secret so it stays on this device (no Universal Clipboard) and disappears after a minute.
@MainActor
func copySecret(_ value: String) {
    #if os(iOS)
    UIPasteboard.general.setItems([["public.utf8-plain-text": value]],
                                  options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
    #else
    let pb = NSPasteboard.general
    pb.clearContents()
    // The nspasteboard.org markers ask clipboard managers and history tools not to keep or show it.
    pb.setString(value, forType: .string)
    pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
    pb.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.TransientType"))
    let count = pb.changeCount // the clear only removes our own copy
    Task { @MainActor in
        try? await Task.sleep(for: .seconds(60))
        if NSPasteboard.general.changeCount == count { NSPasteboard.general.clearContents() }
    }
    #endif
}

extension View {
    /// A text field for a URL or host: no capitals, no autocorrection, the URL keyboard.
    func urlInput() -> some View {
        #if os(iOS)
        keyboardType(.URL).textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        autocorrectionDisabled()
        #endif
    }

    /// A text field for user names, keys and codes: no capitals, no autocorrection.
    func plainInput() -> some View {
        #if os(iOS)
        textInputAutocapitalization(.never).autocorrectionDisabled()
        #else
        autocorrectionDisabled()
        #endif
    }

    /// The small navigation title of a pushed screen or sheet on iOS; nothing on macOS.
    func inlineTitle() -> some View {
        #if os(iOS)
        navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }

    /// Sheets on macOS size to their content, which for forms is too small.
    func sheetSize(width: CGFloat = 520, height: CGFloat = 620) -> some View {
        #if os(macOS)
        frame(minWidth: width, idealWidth: width, minHeight: height, idealHeight: height)
        #else
        self
        #endif
    }

    func usernameContent() -> some View { textContentType(.username) }

    func passwordContent(new: Bool = false) -> some View {
        #if os(iOS)
        textContentType(new ? .newPassword : .password)
        #else
        textContentType(.password)
        #endif
    }
}
