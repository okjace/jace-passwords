import CryptoKit
import Foundation
import Security

/// The vault's cryptography, byte for byte the same as the desktop app (crypto.py), the web engine and Android:
/// scrypt(N=2^17, r=8, p=1) of the master password, XOR an HKDF of the Secret Key, unwraps a random 256-bit vault
/// key; AES-256-GCM with fixed associated data seals the key and the vault.
enum JPCrypto {
    struct Failure: LocalizedError { let message: String; var errorDescription: String? { message } }

    static let aadKey = Data("jace-passwords:key".utf8)
    static let aadData = Data("jace-passwords:data".utf8)
    static let aadRemember = Data("jace-passwords:remembered".utf8)
    private static let b32 = Array("ABCDEFGHJKLMNPQRSTVWXYZ23456789")

    static func rand(_ n: Int) -> Data {
        var d = Data(count: n)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return d
    }

    // MARK: AES-256-GCM: ["iv": b64, "ct": b64 (ciphertext + 16-byte tag)]
    static func seal(_ key: Data, _ plain: Data, _ aad: Data) throws -> [String: Any] {
        let iv = rand(12)
        let box = try AES.GCM.seal(plain, using: SymmetricKey(data: key), nonce: AES.GCM.Nonce(data: iv), authenticating: aad)
        return ["iv": iv.base64EncodedString(), "ct": (box.ciphertext + box.tag).base64EncodedString()]
    }

    static func open(_ key: Data, _ box: [String: Any], _ aad: Data) throws -> Data {
        guard let ivS = box["iv"] as? String, let ctS = box["ct"] as? String, let iv = Data(base64Encoded: ivS),
              let ct = Data(base64Encoded: ctS), ct.count >= 16 else { throw Failure(message: "Wrong master password or Secret Key.") }
        do {
            let sealed = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: iv), ciphertext: ct.prefix(ct.count - 16), tag: ct.suffix(16))
            return try AES.GCM.open(sealed, using: SymmetricKey(data: key), authenticating: aad)
        } catch { throw Failure(message: "Wrong master password or Secret Key.") }
    }

    // MARK: HKDF-SHA256 / PBKDF2 (one iteration, for scrypt)
    static func hkdf(_ ikm: Data, salt: Data, info: String) -> Data {
        let k = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: ikm), salt: salt, info: Data(info.utf8), outputByteCount: 32)
        return k.withUnsafeBytes { Data($0) }
    }

    private static func pbkdf2Once(_ pass: Data, _ salt: Data, _ len: Int) -> Data {
        // An empty HMAC key is the same as 64 zero bytes (HMAC pads keys to the block size).
        let key = SymmetricKey(data: pass.isEmpty ? Data(count: 64) : pass)
        var out = Data(); var block: UInt32 = 1
        while out.count < len {
            var h = HMAC<SHA256>(key: key)
            h.update(data: salt)
            h.update(data: withUnsafeBytes(of: block.bigEndian) { Data($0) })
            out.append(contentsOf: h.finalize())
            block += 1
        }
        return out.prefix(len)
    }

    // MARK: scrypt (RFC 7914)
    static func scrypt(_ pass: Data, _ salt: Data, n: Int, r: Int, p: Int, dkLen: Int) -> Data {
        var b = [UInt8](pbkdf2Once(pass, salt, p * 128 * r))
        let words = 32 * r
        var xy = [UInt32](repeating: 0, count: 64 * r)
        var v = [UInt32](repeating: 0, count: words * n)
        var x = [UInt32](repeating: 0, count: 16)
        for i in 0..<p {
            let bi = i * 128 * r
            for k in 0..<words {
                let o = bi + k * 4
                xy[k] = UInt32(b[o]) | UInt32(b[o + 1]) << 8 | UInt32(b[o + 2]) << 16 | UInt32(b[o + 3]) << 24
            }
            v.withUnsafeMutableBufferPointer { vp in
                xy.withUnsafeMutableBufferPointer { xp in
                    x.withUnsafeMutableBufferPointer { xb in
                        for j in 0..<n {
                            for k in 0..<words { vp[j * words + k] = xp[k] }
                            blockMix(xp, xb, r)
                        }
                        for _ in 0..<n {
                            let j = Int(xp[(2 * r - 1) * 16] & UInt32(n - 1))
                            for k in 0..<words { xp[k] ^= vp[j * words + k] }
                            blockMix(xp, xb, r)
                        }
                    }
                }
            }
            for k in 0..<words {
                let w = xy[k]; let o = bi + k * 4
                b[o] = UInt8(w & 255); b[o + 1] = UInt8((w >> 8) & 255); b[o + 2] = UInt8((w >> 16) & 255); b[o + 3] = UInt8(w >> 24)
            }
        }
        return pbkdf2Once(pass, Data(b), dkLen)
    }

    private static func blockMix(_ xy: UnsafeMutableBufferPointer<UInt32>, _ x: UnsafeMutableBufferPointer<UInt32>, _ r: Int) {
        let y = 32 * r
        for k in 0..<16 { x[k] = xy[(2 * r - 1) * 16 + k] }
        for i in 0..<(2 * r) {
            for k in 0..<16 { x[k] ^= xy[i * 16 + k] }
            salsa8(x)
            for k in 0..<16 { xy[y + i * 16 + k] = x[k] }
        }
        for i in 0..<r { for k in 0..<16 { xy[i * 16 + k] = xy[y + (2 * i) * 16 + k] } }
        for i in 0..<r { for k in 0..<16 { xy[(i + r) * 16 + k] = xy[y + (2 * i + 1) * 16 + k] } }
    }

    @inline(__always) private static func rl(_ a: UInt32, _ s: UInt32) -> UInt32 { (a << s) | (a >> (32 - s)) }

    private static func salsa8(_ b: UnsafeMutableBufferPointer<UInt32>) {
        var x0 = b[0], x1 = b[1], x2 = b[2], x3 = b[3], x4 = b[4], x5 = b[5], x6 = b[6], x7 = b[7]
        var x8 = b[8], x9 = b[9], x10 = b[10], x11 = b[11], x12 = b[12], x13 = b[13], x14 = b[14], x15 = b[15]
        for _ in 0..<4 {
            x4 ^= rl(x0 &+ x12, 7); x8 ^= rl(x4 &+ x0, 9); x12 ^= rl(x8 &+ x4, 13); x0 ^= rl(x12 &+ x8, 18)
            x9 ^= rl(x5 &+ x1, 7); x13 ^= rl(x9 &+ x5, 9); x1 ^= rl(x13 &+ x9, 13); x5 ^= rl(x1 &+ x13, 18)
            x14 ^= rl(x10 &+ x6, 7); x2 ^= rl(x14 &+ x10, 9); x6 ^= rl(x2 &+ x14, 13); x10 ^= rl(x6 &+ x2, 18)
            x3 ^= rl(x15 &+ x11, 7); x7 ^= rl(x3 &+ x15, 9); x11 ^= rl(x7 &+ x3, 13); x15 ^= rl(x11 &+ x7, 18)
            x1 ^= rl(x0 &+ x3, 7); x2 ^= rl(x1 &+ x0, 9); x3 ^= rl(x2 &+ x1, 13); x0 ^= rl(x3 &+ x2, 18)
            x6 ^= rl(x5 &+ x4, 7); x7 ^= rl(x6 &+ x5, 9); x4 ^= rl(x7 &+ x6, 13); x5 ^= rl(x4 &+ x7, 18)
            x11 ^= rl(x10 &+ x9, 7); x8 ^= rl(x11 &+ x10, 9); x9 ^= rl(x8 &+ x11, 13); x10 ^= rl(x9 &+ x8, 18)
            x12 ^= rl(x15 &+ x14, 7); x13 ^= rl(x12 &+ x15, 9); x14 ^= rl(x13 &+ x12, 13); x15 ^= rl(x14 &+ x13, 18)
        }
        b[0] &+= x0; b[1] &+= x1; b[2] &+= x2; b[3] &+= x3; b[4] &+= x4; b[5] &+= x5; b[6] &+= x6; b[7] &+= x7
        b[8] &+= x8; b[9] &+= x9; b[10] &+= x10; b[11] &+= x11; b[12] &+= x12; b[13] &+= x13; b[14] &+= x14; b[15] &+= x15
    }

    // MARK: the key that unwraps the vault key (crypto.py derive_kek)
    static func normalizeSecretKey(_ sk: String) throws -> String {
        var raw = sk.uppercased().filter { $0.isLetter || $0.isNumber }
        if raw.hasPrefix("J1") { raw = String(raw.dropFirst(2)) }
        guard raw.count == 26, raw.allSatisfy({ b32.contains($0) }) else {
            throw Failure(message: "That Secret Key doesn't look right. It starts with J1- and has 26 more letters and numbers.")
        }
        return raw
    }

    static func deriveKek(password: String?, secretKey: String?, salt: Data, kdf: [String: Any], jaceKey: Data?, deviceKey: Data?) throws -> Data {
        switch kdf["name"] as? String {
        case "device":
            guard let dk = deviceKey else { throw Failure(message: "This vault opens only on the device that made it.") }
            return hkdf(dk, salt: salt, info: "jace-passwords device unlock v1")
        case "jace":
            guard let jk = jaceKey else { throw Failure(message: "Sign in with Jace to unlock this vault.") }
            return hkdf(jk, salt: salt, info: "jace-passwords jace unlock v1")
        case "scrypt": break
        default: throw Failure(message: "Unknown key derivation.")
        }
        let n = (kdf["n"] as? Int) ?? 131072, r = (kdf["r"] as? Int) ?? 8, p = (kdf["p"] as? Int) ?? 1
        let k1 = scrypt(Data((password ?? "").utf8), salt, n: n, r: r, p: p, dkLen: 32)
        if let usesSk = kdf["secretKey"] as? Bool, !usesSk { return k1 }
        guard let sk = secretKey else { throw Failure(message: "Enter your Secret Key (it's on your Emergency Kit).") }
        let k2 = hkdf(Data(try normalizeSecretKey(sk).utf8), salt: salt, info: "jace-passwords secret key v1")
        return Data(zip(k1, k2).map { $0 ^ $1 })
    }
}
