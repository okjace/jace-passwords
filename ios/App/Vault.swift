import Foundation
import Security

/// This iPhone's own settings and secrets (Jace sign-in, Secret Key, device key, remembered key), in the Keychain,
/// readable only by this app on this device.
enum DeviceStore {
    private static let account = "jace-passwords-device"
    static func load() -> [String: Any] {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: account,
                                kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data,
              let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return [:] }
        return obj
    }
    @discardableResult static func update(_ change: (inout [String: Any]) -> Void) -> [String: Any] {
        var d = load(); change(&d)
        let data = (try? JSONSerialization.data(withJSONObject: d)) ?? Data()
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrAccount as String: account]
        if SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary) == errSecItemNotFound {
            var add = q; add[kSecValueData as String] = data
            add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(add as CFDictionary, nil)
        }
        return d
    }
}

/// One vault, the same as vault.py / webvault.js / Android: the file is {format, account, kdf, salt, wrappedKey,
/// keyChangedAt, data: AES-GCM(vault key, JSON), updatedAt}; unknown fields in the data survive a save.
final class Vault {
    struct Failure: LocalizedError { let message: String; var errorDescription: String? { message } }
    static let format = "jace-passwords/1"
    private let fileURL: URL = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("vault.json")
    }()

    private(set) var key: Data?
    private(set) var data: [String: Any]?
    private var meta: [String: Any] = [:]
    var lastActivity = Date()
    var unlocked: Bool { data != nil }

    static func now() -> String {
        let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: Date())
    }
    static func newId() -> String { UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased() }
    static func keyMode(_ f: [String: Any]?) -> String {
        switch (f?["kdf"] as? [String: Any])?["name"] as? String { case "jace": return "jace"; case "device": return "device"; default: return "password" }
    }
    static func usesSecretKey(_ f: [String: Any]?) -> Bool {
        guard let k = f?["kdf"] as? [String: Any], k["name"] as? String == "scrypt" else { return false }
        if let b = k["secretKey"] as? Bool { return b }
        return true
    }

    // MARK: files
    func file() -> [String: Any]? {
        guard let d = try? Data(contentsOf: fileURL) else { return nil }
        return try? JSONSerialization.jsonObject(with: d) as? [String: Any]
    }
    var exists: Bool { file() != nil }
    var keyMode: String { Vault.keyMode(file()) }
    private func write(_ f: [String: Any]?) {
        guard let f else { try? FileManager.default.removeItem(at: fileURL); return }
        if let d = try? JSONSerialization.data(withJSONObject: f) { try? d.write(to: fileURL, options: [.atomic, .completeFileProtection]) }
    }

    private func deviceKey(create: Bool = false) -> Data? {
        if let s = DeviceStore.load()["deviceKey"] as? String, let d = Data(base64Encoded: s) { return d }
        guard create else { return nil }
        let k = JPCrypto.rand(32)
        DeviceStore.update { $0["deviceKey"] = k.base64EncodedString() }
        return k
    }

    private static func metaOf(_ f: [String: Any]) -> [String: Any] { var m = f; m["data"] = nil; m["updatedAt"] = nil; return m }

    // MARK: opening
    /// Opens the vault on this phone, or `remote` (a synced copy being restored, then saved here).
    func unlock(password: String?, secretKey: String?, jaceKey: Data?, remote: [String: Any]? = nil) throws {
        guard let f = remote ?? file() else { throw Failure(message: "There's no vault on this phone yet.") }
        guard f["format"] as? String == Vault.format else { throw Failure(message: "This isn't a Jace Passwords vault.") }
        if remote == nil, Vault.keyMode(f) == "password", (password ?? "").isEmpty {
            if DeviceStore.load()["rememberedKey"] != nil { return try unlockRemembered(f) }
            throw Failure(message: "Enter your master password.")
        }
        var sk: String?
        if Vault.usesSecretKey(f) {
            sk = (secretKey?.isEmpty == false ? secretKey : nil) ?? (DeviceStore.load()["secretKey"] as? String)
            if sk == nil { throw Failure(message: "Enter your Secret Key (it's on your Emergency Kit).") }
        }
        guard let salt = Data(base64Encoded: f["salt"] as? String ?? ""), let kdf = f["kdf"] as? [String: Any],
              let wrapped = f["wrappedKey"] as? [String: Any], let box = f["data"] as? [String: Any] else { throw Failure(message: "This vault is damaged.") }
        let kek = try JPCrypto.deriveKek(password: password, secretKey: sk, salt: salt, kdf: kdf, jaceKey: jaceKey, deviceKey: deviceKey())
        let k = try JPCrypto.open(kek, wrapped, JPCrypto.aadKey)
        guard let d = try JSONSerialization.jsonObject(with: try JPCrypto.open(k, box, JPCrypto.aadData)) as? [String: Any] else { throw Failure(message: "This vault is damaged.") }
        key = k; data = d; meta = Vault.metaOf(f)
        if sk != nil, let typed = secretKey, !typed.isEmpty { DeviceStore.update { $0["secretKey"] = typed } }
        if remote != nil { try save() }
        lastActivity = Date()
    }

    private func unlockRemembered(_ f: [String: Any]) throws {
        do {
            guard let dk = deviceKey(), let box = DeviceStore.load()["rememberedKey"] as? [String: Any], let dbox = f["data"] as? [String: Any] else { throw Failure(message: "") }
            let k = try JPCrypto.open(dk, box, JPCrypto.aadRemember)
            guard let d = try JSONSerialization.jsonObject(with: try JPCrypto.open(k, dbox, JPCrypto.aadData)) as? [String: Any] else { throw Failure(message: "") }
            key = k; data = d; meta = Vault.metaOf(f); lastActivity = Date()
        } catch {
            DeviceStore.update { $0["rememberedKey"] = nil }
            throw Failure(message: "Enter your master password.")
        }
    }

    func lock() { key = nil; data = nil }
    var remembered: Bool { DeviceStore.load()["rememberedKey"] != nil && keyMode == "password" }
    func remember(_ on: Bool) throws {
        guard let k = key else { throw Failure(message: "The vault is locked.") }
        let sealed = on ? try JPCrypto.seal(deviceKey(create: true)!, k, JPCrypto.aadRemember) : nil
        DeviceStore.update { $0["rememberedKey"] = sealed }
    }

    // MARK: making one
    /// A new vault; returns the new Secret Key, if one was made (master password and no Jace account).
    func create(password: String?, account: [String: Any]?, jaceKey: Data?) throws -> String? {
        key = JPCrypto.rand(32)
        let t = Vault.now()
        data = ["vaults": [["id": Vault.newId(), "name": "Personal", "icon": "🔐", "color": "#3ddc84", "travelSafe": true, "createdAt": t, "updatedAt": t]],
                "items": [], "settings": ["autoLockMinutes": 10, "clipboardClearSeconds": 30], "generatorHistory": [], "createdAt": t]
        var sk: String?
        if password != nil && account == nil {
            let chars = Array("ABCDEFGHJKLMNPQRSTVWXYZ23456789")
            let r = String(JPCrypto.rand(26).map { chars[Int($0) % chars.count] })
            let a = Array(r)
            sk = "J1-" + [String(a[0..<6]), String(a[6..<11]), String(a[11..<16]), String(a[16..<21]), String(a[21..<26])].joined(separator: "-")
        }
        try wrap(password: password, secretKey: sk, account: account, useSecretKey: sk != nil, jaceKey: jaceKey)
        DeviceStore.update { $0["secretKey"] = sk; $0["rememberedKey"] = nil }
        try save()
        return sk
    }

    func wrap(password: String?, secretKey: String?, account: [String: Any]?, useSecretKey: Bool, jaceKey: Data?) throws {
        guard let k = key else { throw Failure(message: "The vault is locked.") }
        let salt = JPCrypto.rand(16)
        let acct: Any = account ?? meta["account"] ?? NSNull()
        let kdf: [String: Any]
        if password == nil, jaceKey != nil { kdf = ["name": "jace", "sub": (acct as? [String: Any])?["id"] as? String ?? ""] }
        else if password == nil { kdf = ["name": "device"] }
        else if useSecretKey { kdf = ["name": "scrypt", "n": 131072, "r": 8, "p": 1] }
        else { kdf = ["name": "scrypt", "n": 131072, "r": 8, "p": 1, "secretKey": false] }
        let kek = try JPCrypto.deriveKek(password: password, secretKey: secretKey, salt: salt, kdf: kdf, jaceKey: jaceKey,
                                         deviceKey: kdf["name"] as? String == "device" ? deviceKey(create: true) : nil)
        meta = ["format": Vault.format, "account": acct, "kdf": kdf, "salt": salt.base64EncodedString(),
                "wrappedKey": try JPCrypto.seal(kek, k, JPCrypto.aadKey), "keyChangedAt": Vault.now()]
    }

    func setAccount(_ a: [String: Any]?) { meta["account"] = a ?? NSNull() }

    // MARK: saving
    func fileDict() throws -> [String: Any] {
        guard let d = data, let k = key else { throw Failure(message: "The vault is locked.") }
        var f = meta
        f["data"] = try JPCrypto.seal(k, try JSONSerialization.data(withJSONObject: d), JPCrypto.aadData)
        f["updatedAt"] = Vault.now()
        return f
    }
    func save() throws { write(try fileDict()) }

    // MARK: items
    func items(includeTrash: Bool = false) -> [[String: Any]] {
        ((data?["items"] as? [[String: Any]]) ?? []).filter { ($0["purged"] as? Bool) != true && (includeTrash || $0["deletedAt"] == nil) }
    }
    func item(_ id: String) -> [String: Any]? { items(includeTrash: true).first { $0["id"] as? String == id } }

    private func mutateItem(_ id: String, _ change: (inout [String: Any]) -> Void) throws {
        guard var d = data, var arr = d["items"] as? [[String: Any]], let i = arr.firstIndex(where: { $0["id"] as? String == id }) else {
            throw Failure(message: "That item doesn't exist.")
        }
        change(&arr[i]); arr[i]["updatedAt"] = Vault.now()
        d["items"] = arr; data = d
        try save()
    }

    @discardableResult func addItem(type: String, title: String, fields: [String: Any]) throws -> [String: Any] {
        guard var d = data else { throw Failure(message: "The vault is locked.") }
        let t = Vault.now()
        let vaultId = ((d["vaults"] as? [[String: Any]])?.first?["id"] as? String) ?? ""
        let n: [String: Any] = ["id": Vault.newId(), "type": type, "vaultId": vaultId, "title": title.isEmpty ? "Untitled" : title, "favorite": false,
                                "tags": [], "fields": fields, "passwordHistory": [], "createdAt": t, "updatedAt": t, "passwordChangedAt": t]
        d["items"] = ((d["items"] as? [[String: Any]]) ?? []) + [n]
        data = d
        try save()
        return n
    }

    func updateItem(_ id: String, title: String?, fields: [String: Any]?) throws {
        try mutateItem(id) { it in
            if let title { it["title"] = title.isEmpty ? "Untitled" : title }
            if let fields {
                var merged = (it["fields"] as? [String: Any]) ?? [:]
                let oldPw = merged["password"] as? String ?? ""
                fields.forEach { merged[$0.key] = $0.value }
                if !oldPw.isEmpty, merged["password"] as? String != oldPw {
                    it["passwordHistory"] = ((it["passwordHistory"] as? [[String: Any]]) ?? []) + [["password": oldPw, "changedAt": Vault.now()]]
                    it["passwordChangedAt"] = Vault.now()
                }
                it["fields"] = merged
            }
        }
    }
    func trash(_ id: String) throws { try mutateItem(id) { $0["deletedAt"] = Vault.now() } }

    // MARK: sync: newest change wins per item and vault (vault.py merge_remote)
    @discardableResult func merge(_ remote: [String: Any]) throws -> Bool {
        guard var d = data, let k = key else { throw Failure(message: "The vault is locked.") }
        guard let box = remote["data"] as? [String: Any], let plain = try? JPCrypto.open(k, box, JPCrypto.aadData),
              let rd = try JSONSerialization.jsonObject(with: plain) as? [String: Any] else {
            throw Failure(message: "The vault on Jace was made with a different key. Sign out of Jace or reset its copy.")
        }
        var changed = false
        for coll in ["items", "vaults"] {
            var order: [String] = []; var mine: [String: [String: Any]] = [:]
            for x in (d[coll] as? [[String: Any]]) ?? [] { let id = x["id"] as? String ?? ""; if mine[id] == nil { order.append(id) }; mine[id] = x }
            for r in (rd[coll] as? [[String: Any]]) ?? [] {
                let id = r["id"] as? String ?? ""
                if let m = mine[id], (r["updatedAt"] as? String ?? "") <= (m["updatedAt"] as? String ?? "") { continue }
                if mine[id] == nil { order.append(id) }
                mine[id] = r; changed = true
            }
            d[coll] = order.compactMap { mine[$0] }
        }
        var gone = (d["deletedVaults"] as? [String: String]) ?? [:]
        for (id, t) in (rd["deletedVaults"] as? [String: String]) ?? [:] where t > (gone[id] ?? "") { gone[id] = t; changed = true }
        if !gone.isEmpty {
            d["deletedVaults"] = gone
            let vaults = (d["vaults"] as? [[String: Any]]) ?? []
            let keep = vaults.filter { v in let id = v["id"] as? String ?? ""; return !(gone[id] != nil && (v["updatedAt"] as? String ?? "") <= gone[id]!) }
            if !keep.isEmpty && keep.count != vaults.count {
                let ids = Set(keep.compactMap { $0["id"] as? String })
                d["items"] = ((d["items"] as? [[String: Any]]) ?? []).map { var it = $0; if !ids.contains(it["vaultId"] as? String ?? "") { it["vaultId"] = keep[0]["id"] }; return it }
                d["vaults"] = keep
            }
        }
        if let rs = rd["settings"] as? [String: Any], (rs["updatedAt"] as? String ?? "") > ((d["settings"] as? [String: Any])?["updatedAt"] as? String ?? "") {
            d["settings"] = rs; changed = true
        }
        if (remote["keyChangedAt"] as? String ?? "") > (meta["keyChangedAt"] as? String ?? "") {
            for key in ["kdf", "salt", "wrappedKey", "keyChangedAt"] { meta[key] = remote[key] }
            changed = true
        }
        data = d
        if changed { try save() }
        return changed
    }
}
