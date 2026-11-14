#!/usr/bin/env python3
"""Builds the browser extension packages into dist/.

  dist/jace-passwords-<version>-chrome.zip    Chrome, Edge, Brave, Opera, Vivaldi (Web Store upload,
                                              or unzip and "Load unpacked")
  dist/jace-passwords-<version>-firefox.xpi   Firefox / Jace Browser, UNSIGNED. Sign it with
                                              packaging/sign_firefox.py to install it permanently.
                                              Updates itself from this project's own update list.
  dist/jace-passwords-<version>-firefox-store.zip  For the Firefox add-ons store (addons.mozilla.org,
                                              listed): the same, without update_url, because the store
                                              updates listed add-ons itself.
"""
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "extension"
DIST = ROOT / "dist"
SKIP = {".DS_Store"}
# The standalone extension runs the same vault engine as the web app.
SHARED = {"vault/webvault.js": ROOT / "jace_passwords" / "web" / "webvault.js",
          "vault/words.js": ROOT / "jace_passwords" / "web" / "words.js"}


def files():
    return sorted(p for p in EXT.rglob("*") if p.is_file() and p.name not in SKIP and p.name != "manifest.json")


def build(target: str) -> Path:
    manifest = json.loads((EXT / "manifest.json").read_text())
    if target == "chrome":
        manifest["background"] = {"service_worker": "background.js"}  # imports vault/*.js itself
        manifest.pop("browser_specific_settings", None)
    else:
        manifest["background"] = {"scripts": ["vault/words.js", "vault/webvault.js", "mailcodes.js", "background.js"]}
        if target == "firefox-store":
            manifest["browser_specific_settings"]["gecko"].pop("update_url", None)
    version = manifest["version"]
    DIST.mkdir(exist_ok=True)
    out = DIST / f"jace-passwords-{version}-{target}.{'xpi' if target == 'firefox' else 'zip'}"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        for f in files():
            rel = f.relative_to(EXT).as_posix()
            if rel in SHARED:
                continue
            z.write(f, rel)
        for rel, src in SHARED.items():  # the vault engine: always the web app's current copy
            z.write(src, rel)
    return out


if __name__ == "__main__":
    targets = sys.argv[1:] or ["chrome", "firefox", "firefox-store"]
    for t in targets:
        print(build(t))
