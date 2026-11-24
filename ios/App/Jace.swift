import AuthenticationServices
import Foundation
import UIKit

/// The Jace Passwords site (jace-passwords.vercel.app/api/jace/...), with this iPhone's Jace sign-in token, exactly like
/// the browser extension and the Android app: your account, sync of the encrypted vault, and the vault key.
enum JaceAPI {
    static let web = "https://jace-passwords.vercel.app"
    struct Failure: LocalizedError { let message: String; var errorDescription: String? { message } }
    struct SignedOut: LocalizedError { var errorDescription: String? { "Sign in with Jace again." } }

    static func call(_ method: String, _ path: String, token: String, body: [String: Any]? = nil, headers: [String: String] = [:]) async throws -> (Int, [String: Any]) {
        var r = URLRequest(url: URL(string: "\(web)/api/jace/\(path)")!)
        r.httpMethod = method
        r.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        r.setValue("1", forHTTPHeaderField: "X-Jace-Passwords")
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        headers.forEach { r.setValue($0.value, forHTTPHeaderField: $0.key) }
        if let body {
            r.setValue("application/json", forHTTPHeaderField: "Content-Type")
            r.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        let (data, resp) = try await URLSession.shared.data(for: r)
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        return (status, (try? JSONSerialization.jsonObject(with: data) as? [String: Any]) ?? [:])
    }

    static func me(token: String) async throws -> [String: Any] {
        let (s, b) = try await call("GET", "me", token: token)
        if s == 401 { throw SignedOut() }
        guard s == 200, let u = b["user"] as? [String: Any] else { throw Failure(message: "Jace didn't accept the sign-in.") }
        return u
    }

    static func vaultKey(token: String, userId: String) async throws -> Data {
        let (s, b) = try await call("GET", "vault-key", token: token)
        guard s == 200, let k = b["key"] as? String, let d = Data(base64Encoded: k) else {
            throw Failure(message: (b["error_description"] as? String) ?? "Couldn't get your vault key. Sign in with Jace again.")
        }
        guard b["sub"] as? String == userId else { throw Failure(message: "That key is for a different Jace account.") }
        return d
    }

    /// (vault file, version), or (nil, 0) if nothing is synced yet.
    static func pull(token: String) async throws -> ([String: Any]?, Int) {
        let (s, b) = try await call("GET", "sync", token: token)
        if s == 404 { return (nil, 0) }
        if s == 401 { throw SignedOut() }
        guard s == 200, let p = b["payload"] as? String, let d = Data(base64Encoded: p),
              let f = try JSONSerialization.jsonObject(with: d) as? [String: Any] else { throw Failure(message: "Jace sync failed (\(s)).") }
        return (f, b["version"] as? Int ?? 0)
    }

    /// The new version, or -1 if someone else synced first (pull and try again).
    static func push(token: String, file: [String: Any], version: Int) async throws -> Int {
        let payload = try JSONSerialization.data(withJSONObject: file).base64EncodedString()
        let (s, b) = try await call("PUT", "sync", token: token, body: ["payload": payload, "device": "Jace Passwords iPhone"], headers: ["If-Match": "\"\(version)\""])
        if s == 412 { return -1 }
        if s == 401 { throw SignedOut() }
        guard s == 200 else { throw Failure(message: (b["error_description"] as? String) ?? "Jace sync failed (\(s)).") }
        return b["version"] as? Int ?? 0
    }
}

/// "Sign in with Jace" in Apple's sign-in sheet; jacepasswords://auth goes back only to this app.
final class SignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    private var session: ASWebAuthenticationSession?

    func start() async throws -> (token: String, expiresIn: Int) {
        let state = JPCrypto.rand(24).map { String(format: "%02x", $0) }.joined()
        let redirect = "jacepasswords://auth"
        var c = URLComponents(string: "\(JaceAPI.web)/api/jace/signin")!
        c.queryItems = [URLQueryItem(name: "ext_redirect", value: redirect), URLQueryItem(name: "app_state", value: state)]
        let url: URL = try await withCheckedThrowingContinuation { cont in
            let s = ASWebAuthenticationSession(url: c.url!, callbackURLScheme: "jacepasswords") { url, error in
                if let url { cont.resume(returning: url) } else { cont.resume(throwing: error ?? JaceAPI.Failure(message: "Sign-in was cancelled.")) }
            }
            s.presentationContextProvider = self
            s.prefersEphemeralWebBrowserSession = false
            self.session = s
            DispatchQueue.main.async { s.start() }
        }
        var p: [String: String] = [:]
        (URLComponents(string: "x://y?" + (url.fragment ?? ""))?.queryItems ?? []).forEach { p[$0.name] = $0.value ?? "" }
        guard p["app_state"] == state else { throw JaceAPI.Failure(message: "That sign-in didn't come from this app. Try again.") }
        guard let token = p["token"], !token.isEmpty else { throw JaceAPI.Failure(message: p["error"] ?? "Jace didn't sign you in.") }
        return (token, Int(p["expires_in"] ?? "") ?? 86400)
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap { $0.windows }.first { $0.isKeyWindow } ?? ASPresentationAnchor()
    }
}
