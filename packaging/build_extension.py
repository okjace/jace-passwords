#!/usr/bin/env python3
"""Builds the browser extension packages into dist/.

  dist/jace-passwords-<version>-chrome.zip    Chrome, Edge, Brave, Opera, Vivaldi (Web Store upload,
                                              or unzip and "Load unpacked")
  dist/jace-passwords-<version>-firefox.xpi   Firefox / Jace Browser, UNSIGNED. Sign it with
                                              packaging/sign_firefox.py to install it permanently.
                                              Updates itself from this project's own update list.
  dist/jace-passwords-<version>.1-firefox-store.zip  For the Firefox add-ons store (addons.mozilla.org,
                                              listed): the same, without update_url (the store updates it),
                                              numbered <version>.1 because the add-on's unlisted copy (the
                                              GitHub download) already uses <version>, and Mozilla allows
                                              each version number once.
"""
import json
import shutil
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


STORE_SUFFIX = ".1"  # the Firefox store copy of version X is X.1 (see the docstring)


def files():
    return sorted(p for p in EXT.rglob("*") if p.is_file() and p.name not in SKIP and p.name != "manifest.json")


def build(target: str) -> Path:
    manifest = json.loads((EXT / "manifest.json").read_text())
    if target == "chrome":
        manifest["background"] = {"service_worker": "background.js"}  # imports vault/*.js itself
        manifest.pop("browser_specific_settings", None)
    elif target == "safari":  # inside the iPhone app (ios/): Safari wants a non-persistent background page
        manifest["background"] = {"scripts": ["vault/words.js", "vault/webvault.js", "mailcodes.js", "background.js"], "persistent": False}
        manifest.pop("browser_specific_settings", None)
        manifest["permissions"] = [p for p in manifest["permissions"] if p != "identity"]  # Safari signs in through a tab
    else:
        manifest["background"] = {"scripts": ["vault/words.js", "vault/webvault.js", "mailcodes.js", "background.js"]}
        if target == "firefox-store":
            manifest["browser_specific_settings"]["gecko"].pop("update_url", None)
            manifest["version"] += STORE_SUFFIX
    version = manifest["version"]
    DIST.mkdir(exist_ok=True)
    if target == "safari":  # a folder, not a zip: the Xcode build copies it into the Safari extension
        out = DIST / "safari-extension"
        shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True)
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
        for f in files():
            rel = f.relative_to(EXT).as_posix()
            if rel not in SHARED:
                (out / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, out / rel)
        for rel, src in SHARED.items():
            (out / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, out / rel)
        return out
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
