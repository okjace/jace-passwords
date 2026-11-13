import json, tempfile, time, unittest
from pathlib import Path
from jace_passwords import crypto, totp, generator, security, importers
from jace_passwords.vault import Vault, VaultError

class Core(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.v = Vault(self.d)

    def test_create_lock_unlock(self):
        sk = self.v.create("correct horse battery", {"id": "u1", "username": "jace"})
        self.assertTrue(sk.startswith("J1-"))
        self.v.create_item({"type": "login", "title": "GitHub", "fields": {"username": "a", "password": "p1", "urls": ["https://github.com"]}})
        self.v.lock()
        raw = (self.d / "vault.json").read_text()
        self.assertNotIn("GitHub", raw)
        with self.assertRaises(crypto.CryptoError):
            Vault(self.d).unlock("wrong password!!")
        v2 = Vault(self.d); v2.unlock("correct horse battery")
        self.assertEqual(v2.visible_items()[0]["title"], "GitHub")
        with self.assertRaises(crypto.CryptoError):  # right password, wrong secret key
            Vault(self.d).unlock("correct horse battery", crypto.new_secret_key())

    def test_password_history_change_password_and_merge(self):
        self.v.create("correct horse battery", None)
        it = self.v.create_item({"type": "login", "title": "X", "fields": {"password": "old"}})
        self.v.update_item(it["id"], {"fields": {"password": "new"}})
        self.assertEqual(self.v.get_item(it["id"])["passwordHistory"][0]["password"], "old")
        snapshot = self.v.file_dict()
        self.v.change_password("correct horse battery", "another long one")
        self.v.lock(); self.v.unlock("another long one")
        # remote copy with an extra item merges in
        other = Vault(Path(tempfile.mkdtemp())); other._key = self.v._key; other._data = __import__("copy").deepcopy(self.v._data)
        other._file_meta = dict(self.v._file_meta); other.device_path = self.v.device_path; other.path = other.dir / "vault.json"
        other.create_item({"type": "note", "title": "Remote note", "fields": {"body": "hi"}})
        self.assertTrue(self.v.merge_remote(other.file_dict()))
        self.assertIn("Remote note", [i["title"] for i in self.v.visible_items()])

    def test_trash_purge(self):
        self.v.create("correct horse battery", None)
        it = self.v.create_item({"type": "card", "title": "Visa", "fields": {"number": "4111111111111111"}})
        self.v.trash_item(it["id"]); self.assertEqual(self.v.visible_items(), [])
        self.v.restore_item(it["id"]); self.assertEqual(len(self.v.visible_items()), 1)
        self.v.trash_item(it["id"]); self.assertEqual(self.v.empty_trash(), 1)
        self.assertEqual(self.v.visible_items(include_trash=True), [])

    def test_totp_rfc6238(self):
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # "12345678901234567890"
        self.assertEqual(totp.code(secret, at=59)["code"], "287082")
        self.assertEqual(totp.code(f"otpauth://totp/ACME:me?secret={secret}&digits=8&issuer=ACME", at=59)["code"], "94287082")

    def test_generator(self):
        p = generator.random_password(24)
        self.assertEqual(len(p), 24)
        self.assertGreaterEqual(generator.strength(p)["score"], 3)
        self.assertEqual(len(generator.passphrase(5, "-").split("-")), 5)
        self.assertEqual(generator.strength("password")["score"], 0)

    def test_matching_and_watchtower(self):
        it = {"type": "login", "id": "1", "fields": {"urls": ["https://accounts.google.com"], "password": "abc"}}
        self.assertEqual(security.matches(it, "https://mail.google.com/x"), 1)
        self.assertEqual(security.matches(it, "https://accounts.google.com/x"), 2)
        self.assertEqual(security.matches(it, "https://evilgoogle.com"), 0)
        r = security.report([it, dict(it, id="2")])
        self.assertIn("1", r["weak"]); self.assertIn("2", r["reused"]); self.assertIn("1", r["missing2fa"])

    def test_import_csv(self):
        csv = "name,url,username,password,note\nGitHub,https://github.com,me,pw,\n"
        items = importers.parse_csv(csv)
        self.assertEqual(items[0]["fields"]["username"], "me")

if __name__ == "__main__":
    unittest.main()


class NoSecretKey(unittest.TestCase):
    """Vaults linked to a Jace account: master password only."""

    def test_linked_vault_has_no_secret_key(self):
        d = Path(tempfile.mkdtemp())
        v = Vault(d)
        self.assertIsNone(v.create("correct horse battery", {"id": "u1", "username": "jace"}, use_secret_key=False))
        v.create_item({"type": "note", "title": "Hi", "fields": {"body": "x"}})
        f = json.loads((d / "vault.json").read_text())
        self.assertIs(f["kdf"]["secretKey"], False)
        self.assertNotIn("secretKey", v.device())
        # a new device (no device.json at all) unlocks the synced copy with just the password
        other = Vault(Path(tempfile.mkdtemp()))
        other.unlock("correct horse battery", file=f)
        self.assertEqual([i["title"] for i in other.visible_items()], ["Hi"])
        with self.assertRaises(crypto.CryptoError):
            Vault(Path(tempfile.mkdtemp())).unlock("wrong password!!", file=f)
        # changing the password keeps the mode
        v.change_password("correct horse battery", "another long one")
        self.assertFalse(v.uses_secret_key())
        v.lock(); v.unlock("another long one")

    def test_turn_secret_key_on_and_off(self):
        d = Path(tempfile.mkdtemp())
        v = Vault(d)
        sk = v.create("correct horse battery", None)
        self.assertTrue(v.uses_secret_key())
        self.assertIsNone(v.set_secret_key("correct horse battery", False))
        self.assertFalse(v.uses_secret_key())
        f = json.loads((d / "vault.json").read_text())
        Vault(Path(tempfile.mkdtemp())).unlock("correct horse battery", file=f)  # no key needed now
        sk2 = v.set_secret_key("correct horse battery", True)
        self.assertTrue(sk2.startswith("J1-"))
        f = json.loads((d / "vault.json").read_text())
        with self.assertRaises(VaultError):  # a new device must enter the Secret Key again
            Vault(Path(tempfile.mkdtemp())).unlock("correct horse battery", file=f)
        Vault(Path(tempfile.mkdtemp())).unlock("correct horse battery", sk2, file=f)
        with self.assertRaises(VaultError):
            v.set_secret_key("wrong password!!", False)


class UnlockWithJace(unittest.TestCase):
    """Vaults without a master password: the key comes from the Jace Passwords server."""
    KEY = b"k" * 32

    def test_create_unlock_and_switch(self):
        d = Path(tempfile.mkdtemp())
        v = Vault(d)
        self.assertIsNone(v.create(None, {"id": "u1", "username": "jace"}, jace_key=self.KEY))
        self.assertEqual(v.key_mode(), "jace")
        v.create_item({"type": "note", "title": "No password", "fields": {"body": "x"}})
        f = json.loads((d / "vault.json").read_text())
        self.assertEqual(f["kdf"], {"name": "jace", "sub": "u1"})
        self.assertNotIn("No password", json.dumps(f))  # still encrypted at rest
        other = Vault(Path(tempfile.mkdtemp()))
        other.unlock(None, file=f, jace_key=self.KEY)
        self.assertEqual([i["title"] for i in other.visible_items()], ["No password"])
        with self.assertRaises(crypto.CryptoError):
            Vault(Path(tempfile.mkdtemp())).unlock(None, file=f, jace_key=b"x" * 32)  # another account's key
        with self.assertRaises(crypto.CryptoError):
            Vault(Path(tempfile.mkdtemp())).unlock("any password", file=f)  # no key: can't open
        # add a master password -> end-to-end encrypted, no Secret Key
        v.set_key_mode("password", password="now with a password")
        self.assertEqual(v.key_mode(), "password")
        f = json.loads((d / "vault.json").read_text())
        Vault(Path(tempfile.mkdtemp())).unlock("now with a password", file=f)
        # and back to Jace (needs the current password)
        with self.assertRaises(VaultError):
            v.set_key_mode("jace", current="wrong password!!", jace_key=self.KEY)
        v.set_key_mode("jace", current="now with a password", jace_key=self.KEY)
        self.assertEqual(v.key_mode(), "jace")

    def test_needs_an_account(self):
        with self.assertRaises(VaultError):
            Vault(Path(tempfile.mkdtemp())).create(None, None, jace_key=self.KEY)


class VaultKeyService(unittest.TestCase):
    def test_vault_key_route(self):
        import importlib, sys, threading, urllib.error, urllib.request
        from http.server import HTTPServer
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "webapp" / "api"))
        mod = importlib.import_module("jace")
        mod.VAULT_KEY_SECRET = "s" * 64
        calls = []
        def fake(method, path, token=None, **kw):
            calls.append(path)
            if token != "good":
                return 401, {}
            return (200, {"collections": []}) if path == "/api/oauth/sync" else (200, {"sub": "u1"})
        mod._jace = fake
        srv = HTTPServer(("127.0.0.1", 0), mod.handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{srv.server_port}/api/jace/vault-key"
        def get(headers):
            try:
                with urllib.request.urlopen(urllib.request.Request(base, headers=headers)) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, {}
        self.assertEqual(get({"Authorization": "Bearer good"})[0], 403)  # needs the header
        self.assertEqual(get({"X-Jace-Passwords": "1", "Authorization": "Bearer bad"})[0], 401)
        st, body = get({"X-Jace-Passwords": "1", "Authorization": "Bearer good"})
        self.assertEqual((st, body["sub"]), (200, "u1"))
        st2, body2 = get({"X-Jace-Passwords": "1", "Authorization": "Bearer good"})
        self.assertEqual(body["key"], body2["key"])  # stable per account
        srv.shutdown()


class OpenWithoutPassword(unittest.TestCase):
    """No master password and no Jace account: the vault opens on this device, still encrypted."""

    def test_device_vault(self):
        d = Path(tempfile.mkdtemp())
        v = Vault(d)
        self.assertIsNone(v.create(None, None))
        self.assertEqual(v.key_mode(), "device")
        v.create_item({"type": "login", "title": "Secret site", "fields": {"password": "pw"}})
        raw = (d / "vault.json").read_text()
        self.assertNotIn("Secret site", raw)                  # encrypted at rest
        self.assertIn("deviceKey", v.device())
        v.lock()
        v.unlock(None)                                         # no password needed on this device
        self.assertEqual([i["title"] for i in v.visible_items()], ["Secret site"])
        with self.assertRaises(crypto.CryptoError):            # another device can't open it
            Vault(Path(tempfile.mkdtemp())).unlock(None, file=json.loads(raw))
        v.set_key_mode("password", password="x")               # any length works now
        v.lock(); v.unlock("x")
        v.set_key_mode("device", current="x")
        v.lock(); v.unlock(None)
        v.set_key_mode("jace", jace_key=b"k" * 32)             # signing in to Jace: moves to the Jace key
        f = json.loads((d / "vault.json").read_text())
        Vault(Path(tempfile.mkdtemp())).unlock(None, file=f, jace_key=b"k" * 32)

    def test_short_password_ok(self):
        v = Vault(Path(tempfile.mkdtemp()))
        v.create("a", None)
        v.lock(); v.unlock("a")
