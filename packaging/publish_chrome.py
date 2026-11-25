#!/usr/bin/env python3
"""Uploads each release's extension to the Chrome Web Store and submits it for review (Chrome Web Store API v2),
so people who installed it from the store get the update.

CI runs it with three secrets (packaging/chrome_store_setup.py saves them):
    CWS_SERVICE_ACCOUNT   the Google Cloud service account's JSON key (the account is added in the
                          Chrome Web Store Developer Dashboard → Account → Service account)
    CWS_PUBLISHER_ID      Developer Dashboard → Publisher → Settings
    CWS_EXTENSION_ID      the item's ID (lnbpganekbjbcjbchggdbieaballolcl)
"""
import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_extension import build  # noqa: E402

API = "https://chromewebstore.googleapis.com"
SCOPE = "https://www.googleapis.com/auth/chromewebstore"


def call(method, url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {url.split('?')[0]} -> {e.code}: {e.read().decode(errors='replace')[:800]}") from None


def access_token(sa: dict) -> str:
    """A one-hour token for the service account: a signed JWT traded at Google's token endpoint."""
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()  # noqa: E731
    now = int(time.time())
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    claims = b64(json.dumps({"iss": sa["client_email"], "scope": SCOPE, "aud": sa["token_uri"], "iat": now, "exp": now + 3600}).encode())
    key = serialization.load_pem_private_key(sa["private_key"].encode(), password=None)
    sig = b64(key.sign(f"{head}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256()))
    r = call("POST", sa["token_uri"], urllib.parse.urlencode({
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": f"{head}.{claims}.{sig}"}).encode(),
        {"Content-Type": "application/x-www-form-urlencoded"})
    return r["access_token"]


def main() -> int:
    env = {k: os.environ.get(k, "").strip() for k in ("CWS_SERVICE_ACCOUNT", "CWS_PUBLISHER_ID", "CWS_EXTENSION_ID")}
    missing = [k for k, v in env.items() if not v]
    if missing:
        print("Missing:", ", ".join(missing), "- see packaging/chrome_store_setup.py", file=sys.stderr)
        return 2
    token = access_token(json.loads(env["CWS_SERVICE_ACCOUNT"]))
    auth = {"Authorization": f"Bearer {token}"}
    item = f"{API}/v2/publishers/{env['CWS_PUBLISHER_ID']}/items/{env['CWS_EXTENSION_ID']}"
    upload = f"{API}/upload/v2/publishers/{env['CWS_PUBLISHER_ID']}/items/{env['CWS_EXTENSION_ID']}:upload"

    zip_path = build("chrome")
    print(f"Uploading {zip_path.name} to the Chrome Web Store…")
    up = call("POST", upload, zip_path.read_bytes(), {**auth, "Content-Type": "application/zip"})
    state = up.get("uploadState")
    for _ in range(60):  # big uploads finish in the background
        if state != "IN_PROGRESS":
            break
        time.sleep(5)
        state = call("GET", f"{item}:fetchStatus", headers=auth).get("lastAsyncUploadState") or "IN_PROGRESS"
    if state not in ("SUCCEEDED", "SUCCESS"):
        print("Upload didn't succeed:", json.dumps(up)[:800], file=sys.stderr)
        return 1
    pub = call("POST", f"{item}:publish", b"{}", {**auth, "Content-Type": "application/json"})
    print("Submitted for review:", json.dumps(pub)[:300])
    return 0


if __name__ == "__main__":
    sys.exit(main())
