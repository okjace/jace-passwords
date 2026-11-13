#!/usr/bin/env python3
"""Uploads the extension to the Chrome Web Store and publishes it (so Chrome, Edge and Brave users
who installed it from the store get updates automatically).

    CWS_CLIENT_ID=… CWS_CLIENT_SECRET=… CWS_REFRESH_TOKEN=… CWS_EXTENSION_ID=… python3 packaging/publish_chrome.py

One-time setup (the README's "Chrome Web Store" section walks through it):
  1. Register at https://chrome.google.com/webstore/devconsole (one-time $5 fee), upload
     dist/jace-passwords-<version>-chrome.zip by hand once, and fill in the listing. Its item id
     (32 letters) is CWS_EXTENSION_ID.
  2. In Google Cloud, enable the "Chrome Web Store API" and make an OAuth client (Desktop app):
     CWS_CLIENT_ID and CWS_CLIENT_SECRET. Get a refresh token for the
     https://www.googleapis.com/auth/chromewebstore scope: CWS_REFRESH_TOKEN.
  3. Save the four as GitHub secrets; every release then uploads and publishes itself.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_extension import build  # noqa: E402


def call(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {url} -> {e.code}: {e.read().decode(errors='replace')[:800]}") from None


def main() -> int:
    env = {k: os.environ.get(k, "") for k in ("CWS_CLIENT_ID", "CWS_CLIENT_SECRET", "CWS_REFRESH_TOKEN", "CWS_EXTENSION_ID")}
    missing = [k for k, v in env.items() if not v]
    if missing:
        print("Missing:", ", ".join(missing), file=sys.stderr)
        print(__doc__)
        return 2
    token = call("POST", "https://oauth2.googleapis.com/token", urllib.parse.urlencode({
        "client_id": env["CWS_CLIENT_ID"], "client_secret": env["CWS_CLIENT_SECRET"],
        "refresh_token": env["CWS_REFRESH_TOKEN"], "grant_type": "refresh_token"}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"})["access_token"]
    auth = {"Authorization": f"Bearer {token}", "x-goog-api-version": "2"}
    item = env["CWS_EXTENSION_ID"]
    zip_path = build("chrome")
    print(f"Uploading {zip_path.name} to the Chrome Web Store…")
    up = call("PUT", f"https://www.googleapis.com/upload/chromewebstore/v1.1/items/{item}", zip_path.read_bytes(), auth)
    if up.get("uploadState") not in ("SUCCESS", "IN_PROGRESS"):
        print("Upload failed:", json.dumps(up.get("itemError") or up), file=sys.stderr)
        return 1
    pub = call("POST", f"https://www.googleapis.com/chromewebstore/v1.1/items/{item}/publish", b"", {**auth, "Content-Length": "0"})
    print("Published:", ", ".join(pub.get("status") or []), "(Google reviews it before users get it)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
