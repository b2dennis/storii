import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public struct APIError: LocalizedError, Sendable {
    public let status: Int
    public let message: String
    public var unauthorized: Bool { status == 401 }
    public var errorDescription: String? { message }
}

public struct Account: Codable, Sendable {
    public var username: String
    public var kdf: KDF
    public var wrappedKey: String
    public var revision: Int64

    enum CodingKeys: String, CodingKey {
        case username, kdf, revision
        case wrappedKey = "wrapped_key"
    }
}

public struct SessionResponse: Codable, Sendable {
    public var token: String
    public var account: Account
}

public struct RemoteItem: Codable, Equatable, Sendable {
    public var id: String
    public var data: String?
    public var deleted: Bool
    public var revision: Int64

    public init(id: String, data: String?, deleted: Bool = false, revision: Int64 = 0) {
        self.id = id
        self.data = data
        self.deleted = deleted
        self.revision = revision
    }

    enum CodingKeys: String, CodingKey { case id, data, deleted, revision }

    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        data = try c.decodeIfPresent(String.self, forKey: .data)
        deleted = try c.decodeIfPresent(Bool.self, forKey: .deleted) ?? false
        revision = try c.decodeIfPresent(Int64.self, forKey: .revision) ?? 0
    }
}

public struct SyncResponse: Codable, Sendable {
    public var revision: Int64
    public var items: [RemoteItem]
}

public struct Write: Codable, Sendable {
    public var id: String
    public var data: String?
    public var delete: Bool

    public init(id: String, data: String? = nil, delete: Bool = false) {
        self.id = id
        self.data = data
        self.delete = delete
    }

    public func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        if let data { try c.encode(data, forKey: .data) }
        if delete { try c.encode(true, forKey: .delete) }
    }
}

/// The storii v2 HTTP API (api/openapi.yaml).
public struct API: Sendable {
    public let baseURL: String
    public var token: String

    public init(_ baseURL: String, token: String = "") {
        var s = baseURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasSuffix("/") { s.removeLast() }
        self.baseURL = s
        self.token = token
    }

    /// Adds https:// when the user typed only a host.
    public static func normalize(_ server: String) -> String {
        let s = server.trimmingCharacters(in: .whitespacesAndNewlines)
        return s.hasPrefix("http://") || s.hasPrefix("https://") ? s : "https://" + s
    }

    private struct Empty: Codable {}
    private struct ErrorBody: Decodable { let error: String }

    private func call<T: Decodable>(_ method: String, _ path: String, _ body: (any Encodable)? = nil, as: T.Type) async throws -> T {
        guard let url = URL(string: baseURL + path) else { throw StoriiError("Invalid server URL") }
        var req = URLRequest(url: url, timeoutInterval: 60)
        req.httpMethod = method
        if !token.isEmpty { req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization") }
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONEncoder().encode(body)
        }
        let (data, resp) = try await URLSession.shared.data(for: req)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            let msg = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error ?? "Server answered \(status)"
            throw APIError(status: status, message: msg)
        }
        if T.self == Empty.self { return Empty() as! T }
        return try JSONDecoder().decode(T.self, from: data)
    }

    public func ping() async throws {
        struct Ping: Decodable { let api: String? }
        guard try await call("GET", "/api/v2/ping", as: Ping.self).api == "v2" else {
            throw APIError(status: 0, message: "That is not a storii v2 server.")
        }
    }

    public func prelogin(username: String) async throws -> KDF {
        struct R: Decodable { let kdf: KDF }
        return try await call("POST", "/api/v2/prelogin", ["username": username], as: R.self).kdf
    }

    public func login(username: String, authKey: String, device: String) async throws -> SessionResponse {
        try await call("POST", "/api/v2/login", ["username": username, "auth_key": authKey, "device_name": device], as: SessionResponse.self)
    }

    public func register(username: String, kdf: KDF, authKey: String, wrappedKey: String, device: String) async throws -> SessionResponse {
        struct Req: Encodable {
            let username: String, kdf: KDF, auth_key: String, wrapped_key: String, device_name: String
        }
        return try await call("POST", "/api/v2/register",
                              Req(username: username, kdf: kdf, auth_key: authKey, wrapped_key: wrappedKey, device_name: device),
                              as: SessionResponse.self)
    }

    public func logout() async throws { _ = try await call("POST", "/api/v2/logout", as: Empty.self) }
    public func account() async throws -> Account { try await call("GET", "/api/v2/account", as: Account.self) }
    public func sync(since: Int64) async throws -> SyncResponse { try await call("GET", "/api/v2/sync?since=\(since)", as: SyncResponse.self) }

    public func write(_ writes: [Write]) async throws -> Int64 {
        struct Req: Encodable { let writes: [Write] }
        struct R: Decodable { let revision: Int64 }
        return try await call("POST", "/api/v2/items", Req(writes: writes), as: R.self).revision
    }
}
