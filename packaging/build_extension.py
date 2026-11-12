#!/usr/bin/env python3
"""Builds the browser extension packages into dist/.

  dist/jace-passwords-<version>-chrome.zip    Chrome, Edge, Brave, Opera, Vivaldi (Web Store upload,
                                              or unzip and "Load unpacked")
  dist/jace-passwords-<version>-firefox.xpi   Firefox / Jace Browser, UNSIGNED. Sign it with
                                              packaging/sign_firefox.py to install it permanently.
"""
import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXT = ROOT / "extension"
DIST = ROOT / "dist"
SKIP = {".DS_Store"}


def files():
    return sorted(p for p in EXT.rglob("*") if p.is_file() and p.name not in SKIP and p.name != "manifest.json")


def build(target: str) -> Path:
    manifest = json.loads((EXT / "manifest.json").read_text())
    if target == "chrome":
        manifest["background"] = {"service_worker": "background.js"}
        manifest.pop("browser_specific_settings", None)
    else:
        manifest["background"] = {"scripts": ["background.js"]}
    version = manifest["version"]
    DIST.mkdir(exist_ok=True)
    out = DIST / f"jace-passwords-{version}-{target}.{'zip' if target == 'chrome' else 'xpi'}"
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        for f in files():
            z.write(f, f.relative_to(EXT).as_posix())
    return out


if __name__ == "__main__":
    targets = sys.argv[1:] or ["chrome", "firefox"]
    for t in targets:
        print(build(t))
