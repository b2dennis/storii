import Foundation

/// URL matching, as internal/vault/match.go: the same host or a subdomain of the context's host, ignoring the port
/// and a leading "www.".
public enum Match {
    public static func host(_ raw: String?) -> String {
        var s = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { return "" }
        if !s.contains("://") { s = "https://" + s }
        let afterScheme = s[s.range(of: "://")!.upperBound...]
        var authority = String(afterScheme.prefix { $0 != "/" && $0 != "?" && $0 != "#" })
        if let at = authority.lastIndex(of: "@") { authority = String(authority[authority.index(after: at)...]) }
        var h: String
        if authority.hasPrefix("[") {
            h = String(authority.dropFirst().prefix { $0 != "]" })
        } else if let colon = authority.lastIndex(of: ":"),
                  authority[authority.index(after: colon)...].allSatisfy(\.isASCII) && authority[authority.index(after: colon)...].allSatisfy(\.isNumber) {
            h = String(authority[..<colon])
        } else {
            h = authority
        }
        h = h.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        if h.hasPrefix("www.") { h.removeFirst(4) }
        return h
    }

    public static func matchesHost(contextURL: String, pageHost: String) -> Bool {
        let ch = host(contextURL), ph = host(pageHost)
        if ch.isEmpty || ph.isEmpty { return false }
        return ph == ch || ph.hasSuffix("." + ch)
    }
}
