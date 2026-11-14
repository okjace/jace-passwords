#!/usr/bin/env python3
"""Gets the Firefox / Jace Browser extension signed by Mozilla so it installs permanently.

Firefox and Jace Browser only keep add-ons that Mozilla has signed; unsigned ones
load as "temporary" and vanish on restart. This uploads the extension to
addons.mozilla.org as an UNLISTED add-on: Mozilla signs it automatically (usually
within minutes), it isn't published in the store, and you get a signed .xpi back.

One-time setup: sign in at https://addons.mozilla.org/developers/addon/api/key/ and
generate API credentials, then:

    export AMO_JWT_ISSUER="user:12345:67"
    export AMO_JWT_SECRET="..."
    python3 packaging/sign_firefox.py

Install the result: Jace Browser / Firefox -> about:addons -> gear icon ->
"Install Add-on From File..." -> dist/jace-passwords-<version>-signed.xpi.
Bump "version" in extension/manifest.json for every new upload.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_extension import DIST, EXT, build  # noqa: E402

API = os.environ.get("AMO_API", "https://addons.mozilla.org/api/v5")


def jwt(issuer: str, secret: str) -> str:
    def enc(obj):
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()
    now = int(time.time())
    msg = enc({"alg": "HS256", "typ": "JWT"}) + "." + enc({"iss": issuer, "jti": secrets.token_hex(16), "iat": now, "exp": now + 60})
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), msg.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return f"{msg}.{sig}"


class Amo:
    def __init__(self, issuer, secret):
        self.issuer, self.secret = issuer, secret

    def request(self, method, path, body=None, form=None, raw=False):
        url = path if path.startswith("http") else API + path
        headers = {"Authorization": "JWT " + jwt(self.issuer, self.secret), "Accept": "application/json"}
        data = None
        if form is not None:
            boundary = uuid.uuid4().hex
            parts = []
            for k, v in form.items():
                if isinstance(v, Path):
                    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"; filename="{v.name}"\r\n'
                                 f"Content-Type: application/x-xpinstall\r\n\r\n".encode() + v.read_bytes() + b"\r\n")
                else:
                    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
            data = b"".join(parts) + f"--{boundary}--\r\n".encode()
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                content = r.read()
                return content if raw else (json.loads(content) if content else {})
        except urllib.error.HTTPError as e:
            detail = e.read().decode(errors="replace")[:1500]
            raise RuntimeError(f"{method} {url} -> {e.code}: {detail}") from None


def send_to_store(amo, guid):
    """Also sends this release to the Firefox add-ons store (listed), as version X.1. Mozilla reviews it and
    the store updates everyone who installed from there. Doesn't wait, and never fails the release."""
    try:
        store = build("firefox-store")
        print(f"Sending {store.name} to the Firefox add-ons store (listed)…")
        up = amo.request("POST", "/addons/upload/", form={"upload": store, "channel": "listed"})
        while not up.get("processed"):
            time.sleep(3)
            up = amo.request("GET", f"/addons/upload/{up['uuid']}/")
        if not up.get("valid"):
            print("::warning::The store copy didn't pass Mozilla's validator; the GitHub copy is unaffected.")
            return
        amo.request("POST", f"/addons/addon/{guid}/versions/", body={"upload": up["uuid"]})
        print("Sent to the add-ons store; it goes live after Mozilla's review.")
    except RuntimeError as e:
        print(f"::warning::Couldn't send the store copy: {e}")


def main() -> int:
    issuer, secret = os.environ.get("AMO_JWT_ISSUER"), os.environ.get("AMO_JWT_SECRET")
    if not issuer or not secret:
        if not sys.stdin.isatty():
            print(__doc__)
            print("Set AMO_JWT_ISSUER and AMO_JWT_SECRET first.", file=sys.stderr)
            return 2
        import getpass
        print("Your keys are at https://addons.mozilla.org/developers/addon/api/key/")
        issuer = issuer or input("JWT issuer (user:…): ").strip()
        secret = secret or getpass.getpass("JWT secret (hidden while you type): ").strip()
        if not issuer or not secret:
            print("Both are needed.", file=sys.stderr)
            return 2
    secret = secret.strip()
    if "." in secret or "…" in secret or len(secret) < 40:
        print("AMO_JWT_SECRET looks shortened (addons.mozilla.org shows a saved secret as 'abcd....wxyz', and "
              "copying it copies the dots). Click 'Revoke and regenerate credentials' and copy the new secret "
              "right away: it's 64 characters, 0-9 and a-f.", file=sys.stderr)
        return 2
    manifest = json.loads((EXT / "manifest.json").read_text())
    guid =manifest["browser_specific_settings"]["gecko"]["id"]
    version = manifest["version"]
    xpi = build("firefox")
    amo = Amo(issuer, secret)
    if os.environ.get("AMO_LISTED", "").strip() in ("1", "true", "yes"):
        send_to_store(amo, guid)

    channel = "unlisted"
    print(f"Uploading {xpi.name} ({channel})…")
    up = amo.request("POST", "/addons/upload/", form={"upload": xpi, "channel": channel})
    while not up.get("processed"):
        time.sleep(3)
        up = amo.request("GET", f"/addons/upload/{up['uuid']}/")
    if not up.get("valid"):
        print("Mozilla's validator rejected it:")
        for m in (up.get("validation") or {}).get("messages", []):
            if m.get("type") == "error":
                print(" -", m.get("message"), m.get("file") or "")
        return 1
    print("Validated. Creating the signed version…")
    try:  # first time: creates the add-on with this version
        amo.request("PUT", f"/addons/addon/{guid}/", body={"version": {"upload": up["uuid"]}})
    except RuntimeError as first:
        try:  # the add-on exists: add this version to it
            amo.request("POST", f"/addons/addon/{guid}/versions/", body={"upload": up["uuid"]})
        except RuntimeError as second:
            if "already exists" not in str(second).lower():
                raise RuntimeError(f"{first}\n{second}") from None
            print("This version was uploaded before; waiting for its signature.")

    print("Waiting for Mozilla to sign it (usually a few minutes)…")
    for _ in range(120):
        v = amo.request("GET", f"/addons/addon/{guid}/versions/v{version}/")
        f = v.get("file") or {}
        if f.get("status") == "public" and f.get("url"):
            out = DIST / f"jace-passwords-{version}-signed.xpi"
            out.write_bytes(amo.request("GET", f["url"], raw=True))
            print(f"Signed: {out}")
            print("Install: about:addons → gear → Install Add-on From File…")
            return 0
        if f.get("status") == "disabled":
            print("Mozilla didn't approve this version. Check https://addons.mozilla.org/developers/")
            return 1
        time.sleep(10)
    print("Still not signed after 20 minutes. Run this again later (it will pick up the same version).")
    return 1


if __name__ == "__main__":
    sys.exit(main())
