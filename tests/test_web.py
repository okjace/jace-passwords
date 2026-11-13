"""The web app's in-browser vault (webvault.js) shares data with the Python app."""
import json
import re
import unittest
from pathlib import Path

from jace_passwords.generator import COMMON, SYMBOLS, WORDS
from jace_passwords.security import MULTI_PART_TLDS, TWO_FA_SITES

WEB = Path(__file__).resolve().parent.parent / "jace_passwords" / "web"


class WebData(unittest.TestCase):
    def test_words_js_matches_python(self):
        data = json.loads(re.search(r"globalThis\.JP_DATA = (\{.*\});", (WEB / "words.js").read_text()).group(1))
        self.assertEqual(data["words"], WORDS)
        self.assertEqual(set(data["common"]), COMMON)
        self.assertEqual(data["symbols"], SYMBOLS)
        self.assertEqual(set(data["twoFaSites"]), TWO_FA_SITES)
        self.assertEqual(set(data["multiPartTlds"]), MULTI_PART_TLDS)

    def test_same_vault_format(self):
        js = (WEB / "webvault.js").read_text()
        for needle in ('"jace-passwords/1"', '"jace-passwords:key"', '"jace-passwords:data"',
                       '"jace-passwords secret key v1"', "n: 131072, r: 8, p: 1"):
            self.assertIn(needle, js)


if __name__ == "__main__":
    unittest.main()


class ExtensionShares(unittest.TestCase):
    def test_extension_has_the_current_vault_engine(self):
        ext = WEB.parent.parent / "extension" / "vault"
        for name in ("webvault.js", "words.js"):
            self.assertEqual((ext / name).read_bytes(), (WEB / name).read_bytes(),
                             f"extension/vault/{name} is out of date: cp jace_passwords/web/{name} extension/vault/")
