import tempfile, time, unittest
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
