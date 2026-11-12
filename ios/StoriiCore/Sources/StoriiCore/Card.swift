import Foundation

/// Card checks, as internal/vault/card.go (shared cases: testdata/cards.json).
public enum Card {
    public static func digits(_ number: String) -> String { String(number.filter { $0.isASCII && $0.isNumber }) }

    public static func brand(_ number: String) -> String {
        let d = Array(digits(number))
        func p(_ n: Int) -> Int { d.count >= n ? Int(String(d[0..<n]))! : -1 }
        switch true {
        case p(2) == 34 || p(2) == 37: return "amex"
        case (300...305).contains(p(3)) || p(2) == 36 || p(2) == 38: return "diners"
        case (3528...3589).contains(p(4)): return "jcb"
        case p(1) == 4: return "visa"
        case (51...55).contains(p(2)) || (2221...2720).contains(p(4)): return "mastercard"
        case p(4) == 6011 || p(2) == 65 || (644...649).contains(p(3)): return "discover"
        case p(2) == 62: return "unionpay"
        case [5018, 5020, 5038, 5893, 6304, 6759, 6761, 6762, 6763, 604].contains(p(4)): return "maestro"
        default: return ""
        }
    }

    public static func displayBrand(_ number: String) -> String {
        switch brand(number) {
        case "amex": return "American Express"
        case "jcb": return "JCB"
        case "unionpay": return "UnionPay"
        case let b: return b.prefix(1).uppercased() + b.dropFirst()
        }
    }

    public static func valid(_ number: String) -> Bool {
        let d = digits(number)
        guard (12...19).contains(d.count) else { return false }
        var sum = 0
        for (i, c) in d.reversed().enumerated() {
            var n = Int(String(c))!
            if i % 2 == 1 { n *= 2; if n > 9 { n -= 9 } }
            sum += n
        }
        return sum % 10 == 0
    }

    public static func masked(_ number: String) -> String { "•••• " + digits(number).suffix(4) }

    /// "12/29", "1/30", "12/2029" or "1229" as "MM/YY"; "" if not a valid month.
    public static func normalizeExpiry(_ input: String) -> String {
        let s = input.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: " ", with: "")
        var m: Substring, y: Substring
        if let slash = s.firstIndex(of: "/") {
            m = s[..<slash]; y = s[s.index(after: slash)...]
        } else if s.count == 4 || s.count == 6 {
            m = s.prefix(2); y = s.dropFirst(2)
        } else { return "" }
        if y.count == 4 { y = y.dropFirst(2) }
        guard let mi = Int(m), y.count == 2, y.allSatisfy({ $0.isASCII && $0.isNumber }), (1...12).contains(mi) else { return "" }
        return String(format: "%02d/", mi) + y
    }
}
