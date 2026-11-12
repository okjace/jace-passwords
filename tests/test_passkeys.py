"""Passkeys: register + sign in, verified the way a website (relying party) would."""
import hashlib, json, os, struct, tempfile, unittest
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jace_passwords import passkeys as pk
from jace_passwords.vault import Vault


def cbor_load(b, i=0):
    """Tiny CBOR decoder for the test (ints, bytes, text, arrays, maps)."""
    ib = b[i]; major, info = ib >> 5, ib & 31; i += 1
    if info < 24: n = info
    else:
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]; n = int.from_bytes(b[i:i + size], "big"); i += size
    if major == 0: return n, i
    if major == 1: return -1 - n, i
    if major == 2: return b[i:i + n], i + n
    if major == 3: return b[i:i + n].decode(), i + n
    if major == 4:
        out = []
        for _ in range(n): v, i = cbor_load(b, i); out.append(v)
        return out, i
    if major == 5:
        out = {}
        for _ in range(n): k, i = cbor_load(b, i); v, i = cbor_load(b, i); out[k] = v
        return out, i
    raise ValueError(major)


def client_data(kind, challenge, origin):
    return json.dumps({"type": kind, "challenge": pk.b64u(challenge), "origin": origin, "crossOrigin": False},
                      separators=(",", ":")).encode()


class Passkeys(unittest.TestCase):
    def setUp(self):
        self.v = Vault(Path(tempfile.mkdtemp()))
        self.v.create("correct horse battery", None)

    def test_register_then_sign_in(self):
        origin, rp = "https://login.example.com", "example.com"
        ch = os.urandom(32)
        stored, resp = pk.register(rp, origin, client_data("webauthn.create", ch, origin),
                                   {"id": pk.b64u(b"user-1"), "name": "jace@example.com", "displayName": "Jace"}, [-7, -257])
        item = self.v.save_passkey(stored, "Example")
        # --- what the website checks at registration ---
        att, _ = cbor_load(pk.b64u_dec(resp["attestationObject"]))
        self.assertEqual(att["fmt"], "none")
        ad = att["authData"]
        self.assertEqual(ad[:32], hashlib.sha256(rp.encode()).digest())
        self.assertTrue(ad[32] & 0x01 and ad[32] & 0x04 and ad[32] & 0x40)
        clen = struct.unpack(">H", ad[53:55])[0]
        self.assertEqual(pk.b64u(ad[55:55 + clen]), resp["credentialId"])
        cose, _ = cbor_load(ad, 55 + clen)
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()).public_key()
        # --- sign in ---
        ch2 = os.urandom(32)
        [(it, p)] = self.v.passkeys_for(rp)
        a = pk.assert_(p, rp, origin, client_data("webauthn.get", ch2, origin))
        signed = pk.b64u_dec(a["authenticatorData"]) + hashlib.sha256(pk.b64u_dec(a["clientDataJSON"])).digest()
        pub.verify(pk.b64u_dec(a["signature"]), signed, ec.ECDSA(hashes.SHA256()))  # raises if bad
        self.assertEqual(pk.b64u_dec(a["userHandle"]), b"user-1")
        self.assertEqual(json.loads(pk.b64u_dec(a["clientDataJSON"]))["challenge"], pk.b64u(ch2))
        # SPKI public key matches too
        spki = serialization.load_der_public_key(pk.b64u_dec(resp["publicKey"]))
        self.assertEqual(spki.public_numbers(), pub.public_numbers())
        # the private key is stripped from what the app window sees, and survives an edit
        snap = [i for i in self.v.snapshot()["items"] if i["id"] == item["id"]][0]
        self.assertNotIn("privateKey", snap["fields"]["passkeys"][0])
        self.v.update_item(item["id"], {"fields": snap["fields"]})
        self.assertIn("privateKey", self.v.get_item(item["id"])["fields"]["passkeys"][0])
        # deleting it from the list removes it
        self.v.update_item(item["id"], {"fields": {**snap["fields"], "passkeys": []}})
        self.assertEqual(self.v.passkeys_for(rp), [])

    def test_origin_rules(self):
        for origin, rp in [("http://example.com", "example.com"), ("https://evil.com", "example.com"),
                           ("https://example.com", "com"), ("https://notexample.com", "example.com")]:
            with self.assertRaises(pk.PasskeyError, msg=(origin, rp)):
                pk.check_origin(origin, rp)
        pk.check_origin("https://a.b.example.com", "example.com")
        pk.check_origin("http://localhost:8000", "localhost")

    def test_same_account_replaces(self):
        o, rp, u = "https://example.com", "example.com", {"id": "dXNlcg", "name": "me"}
        for _ in range(2):
            s, _ = pk.register(rp, o, client_data("webauthn.create", b"x", o), u, [-7])
            self.v.save_passkey(s, "Example")
        self.assertEqual(len(self.v.passkeys_for(rp)), 1)

if __name__ == "__main__":
    unittest.main()
