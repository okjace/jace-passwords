import Foundation
import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// The app's state: the one vault on this iPhone, the Jace sign-in, sync and updates.
@MainActor
final class Model: ObservableObject {
    let vault = Vault()
    @Published var tick = 0          // bumped on every change, so views redraw
    @Published var syncStatus = ""
    @Published var update: (version: String, page: String)?
    private let signIn = SignIn()

    func changed() { tick += 1 }

    // MARK: Jace sign-in
    var token: String? {
        let d = DeviceStore.load()
        guard let t = d["token"] as? String, !t.isEmpty else { return nil }
        if let exp = d["tokenExpires"] as? Double, exp > 0, exp < Date().timeIntervalSince1970 { return nil }
        return t
    }
    var account: [String: Any]? { DeviceStore.load()["user"] as? [String: Any] }
    var signedIn: Bool { token != nil }

    func startSignIn() async throws {
        let (token, expiresIn) = try await signIn.start()
        DeviceStore.update { $0["token"] = token; $0["tokenExpires"] = Date().timeIntervalSince1970 + Double(expiresIn) }
        let user = try await JaceAPI.me(token: token)
        DeviceStore.update { $0["user"] = user }
        if vault.unlocked { vault.setAccount(user); try? vault.save(); await sync() }
        changed()
    }

    func signOut() {
        DeviceStore.update { $0["token"] = nil; $0["tokenExpires"] = nil; $0["user"] = nil }
        syncStatus = ""; changed()
    }

    private func jaceKey() async throws -> Data {
        guard let t = token, let id = account?["id"] as? String else { throw JaceAPI.Failure(message: "Sign in with Jace to unlock this vault.") }
        return try await JaceAPI.vaultKey(token: t, userId: id)
    }

    // MARK: opening
    func unlock(password: String?, secretKey: String?) async throws {
        let jk = vault.keyMode == "jace" ? try await jaceKey() : nil
        let v = vault
        try await Task.detached { try v.unlock(password: password, secretKey: secretKey, jaceKey: jk) }.value // scrypt: a few seconds
        changed()
        Task { await sync() }
    }

    func restore(password: String?, secretKey: String?) async throws {
        guard let t = token else { throw JaceAPI.SignedOut() }
        guard let remote = try await JaceAPI.pull(token: t).0 else { throw JaceAPI.Failure(message: "There's no vault on your Jace account yet.") }
        let jk = Vault.keyMode(remote) == "jace" ? try await jaceKey() : nil
        let v = vault
        try await Task.detached { try v.unlock(password: password, secretKey: secretKey, jaceKey: jk, remote: remote) }.value
        changed()
        Task { await sync() }
    }

    func create(password: String?) async throws -> String? {
        let acct = account
        let jk = (password == nil && acct != nil) ? try await jaceKey() : nil
        let v = vault
        let sk = try await Task.detached { try v.create(password: password, account: acct, jaceKey: jk) }.value
        changed()
        Task { await sync() }
        return sk
    }

    func remoteVault() async -> [String: Any]? {
        guard let t = token else { return nil }
        return try? await JaceAPI.pull(token: t).0
    }

    func lock() { vault.lock(); changed() }

    /// Opens without typing anything where the vault allows it (no password here, Jace account, remembered).
    func autoOpen() async {
        guard vault.exists, !vault.unlocked else { return }
        let m = vault.keyMode
        if vault.remembered || m == "device" || (m == "jace" && signedIn) { try? await unlock(password: nil, secretKey: nil) }
    }

    func checkAutoLock() {
        guard vault.unlocked, vault.keyMode == "password", !vault.remembered else { return }
        let minutes = ((vault.data?["settings"] as? [String: Any])?["autoLockMinutes"] as? Int) ?? 10
        if minutes > 0, Date().timeIntervalSince(vault.lastActivity) > Double(minutes * 60) { lock() }
    }

    // MARK: sync (vault.py sync_now)
    func sync() async {
        guard let t = token, vault.unlocked else { return }
        syncStatus = "Syncing…"
        do {
            for tries in 0...3 {
                let (remote, version) = try await JaceAPI.pull(token: t)
                if let remote { try vault.merge(remote) }
                let v = try await JaceAPI.push(token: t, file: try vault.fileDict(), version: version)
                if v < 0 && tries < 3 { continue }
                DeviceStore.update { $0["syncVersion"] = v }
                break
            }
            syncStatus = "Synced"
        } catch is JaceAPI.SignedOut {
            signOut(); syncStatus = "Signed out of Jace"
        } catch {
            syncStatus = "Sync failed: \(error.localizedDescription)"
        }
        changed()
    }

    // MARK: copying: marked local-only, cleared after 30 seconds
    func copy(_ text: String) {
        UIPasteboard.general.setItems([[UTType.plainText.identifier: text]], options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(30)])
    }

    // MARK: updates: the newest release on GitHub; installed through AltStore / SideStore
    var version: String { Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0" }
    func checkUpdates() async {
        var r = URLRequest(url: URL(string: "https://api.github.com/repos/okjace/jace-passwords/releases/latest")!)
        r.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        guard let res = try? await URLSession.shared.data(for: r), let rel = try? JSONSerialization.jsonObject(with: res.0) as? [String: Any],
              let tag = rel["tag_name"] as? String else { return }
        let v = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        update = Model.newer(v, version) ? (v, rel["html_url"] as? String ?? "") : nil
    }
    static func newer(_ a: String, _ b: String) -> Bool {
        let x = a.split(separator: ".").map { Int($0) ?? 0 }, y = b.split(separator: ".").map { Int($0) ?? 0 }
        for i in 0..<max(x.count, y.count) { let d = (i < x.count ? x[i] : 0) - (i < y.count ? y[i] : 0); if d != 0 { return d > 0 } }
        return false
    }
    /// The AltStore / SideStore source: add it once and they update Jace Passwords from it.
    static let source = "https://jace-passwords.vercel.app/api/jace/altstore"
}
