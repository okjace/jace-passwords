import CryptoKit
import Foundation

/// Two-factor codes (TOTP, RFC 6238) and Steam Guard codes, like totp.py, webvault.js and the Android app.
enum Totp {
    struct Config { var secret: String, digits: Int, period: Int, algorithm: String, steam: Bool }
    struct Code { let code: String, period: Int, remaining: Int }
    struct Failure: LocalizedError { let message: String; var errorDescription: String? { message } }

    private static let steamChars = Array("23456789BCDFGHJKMNPQRTVWXY")
    private static let b32 = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    private static func clean(_ s: String) -> String { s.filter { !$0.isWhitespace && $0 != "-" }.uppercased() }

    static func parse(_ raw: String) throws -> Config {
        var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if value.hasPrefix("{") { // a Steam Desktop Authenticator .maFile
            guard let obj = try? JSONSerialization.jsonObject(with: Data(value.utf8)) as? [String: Any],
                  let shared = obj["shared_secret"] as? String, let bytes = Data(base64Encoded: shared) else {
                throw Failure(message: "That isn't a Steam Guard file (it needs a shared_secret).")
            }
            value = "steam://" + base32Encode(bytes)
        }
        if value.lowercased().hasPrefix("steam://") {
            let c = Config(secret: clean(String(value.dropFirst(8))), digits: 5, period: 30, algorithm: "SHA1", steam: true)
            _ = try base32(c.secret); return c
        }
        if value.lowercased().hasPrefix("otpauth://"), let u = URLComponents(string: value) {
            var q: [String: String] = [:]
            u.queryItems?.forEach { q[$0.name.lowercased()] = $0.value ?? "" }
            let host = (u.host ?? "").lowercased()
            if host == "steam" || q["encoder"]?.lowercased() == "steam" {
                let c = Config(secret: clean(q["secret"] ?? ""), digits: 5, period: 30, algorithm: "SHA1", steam: true)
                _ = try base32(c.secret); return c
            }
            guard host == "totp" else { throw Failure(message: "Only time-based (TOTP) and Steam Guard codes are supported.") }
            let c = Config(secret: clean(q["secret"] ?? ""), digits: Int(q["digits"] ?? "") ?? 6, period: Int(q["period"] ?? "") ?? 30,
                           algorithm: (q["algorithm"] ?? "SHA1").uppercased(), steam: false)
            guard ["SHA1", "SHA256", "SHA512"].contains(c.algorithm), (6...8).contains(c.digits), (10...120).contains(c.period) else {
                throw Failure(message: "Unsupported two-factor settings.")
            }
            _ = try base32(c.secret); return c
        }
        let c = Config(secret: clean(value), digits: 6, period: 30, algorithm: "SHA1", steam: false)
        _ = try base32(c.secret); return c
    }

    private static func base32(_ s: String) throws -> Data {
        guard !s.isEmpty else { throw Failure(message: "That two-factor secret is empty.") }
        var bits = 0, v = 0, out = Data()
        for c in s where c != "=" {
            guard let i = b32.firstIndex(of: c) else { throw Failure(message: "That isn't a valid two-factor secret (it should be base32 letters A–Z and 2–7).") }
            v = (v << 5) | i; bits += 5
            if bits >= 8 { out.append(UInt8((v >> (bits - 8)) & 255)); bits -= 8 }
        }
        return out
    }

    private static func base32Encode(_ d: Data) -> String {
        var s = "", bits = 0, v = 0
        for b in d { v = (v << 8) | Int(b); bits += 8; while bits >= 5 { s.append(b32[(v >> (bits - 5)) & 31]); bits -= 5 } }
        if bits > 0 { s.append(b32[(v << (5 - bits)) & 31]) }
        return s
    }

    static func code(_ value: String, at date: Date = Date()) throws -> Code {
        let c = try parse(value)
        let now = Int(date.timeIntervalSince1970)
        let counter = UInt64(now / c.period)
        let msg = withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        let key = SymmetricKey(data: try base32(c.secret))
        let mac: [UInt8]
        switch c.algorithm {
        case "SHA256": mac = Array(HMAC<SHA256>.authenticationCode(for: msg, using: key))
        case "SHA512": mac = Array(HMAC<SHA512>.authenticationCode(for: msg, using: key))
        default: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: msg, using: key))
        }
        let off = Int(mac[mac.count - 1] & 15)
        var full = (UInt32(mac[off] & 0x7f) << 24) | (UInt32(mac[off + 1]) << 16) | (UInt32(mac[off + 2]) << 8) | UInt32(mac[off + 3])
        var text = ""
        if c.steam {
            for _ in 0..<5 { text.append(steamChars[Int(full % UInt32(steamChars.count))]); full /= UInt32(steamChars.count) }
        } else {
            var p: UInt32 = 1; for _ in 0..<c.digits { p *= 10 }
            text = String(full % p); while text.count < c.digits { text = "0" + text }
        }
        return Code(code: text, period: c.period, remaining: c.period - now % c.period)
    }
}
