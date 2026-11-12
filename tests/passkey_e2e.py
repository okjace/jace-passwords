#!/usr/bin/env python3
"""End-to-end passkey check in a real browser, without installing the extension.

    JACE_PASSWORDS_HOME=/tmp/jp-e2e python3 tests/passkey_e2e.py

Starts Jace Passwords (a fresh test vault, password "test-vault-pass-123") and a
fake website at http://localhost:47699/tests/passkey-test.html. The page loads
the extension's passkey-page.js and content.js with a stand-in for the extension
background (/bg below, which builds clientDataJSON exactly like background.js),
and the site verifies registration and sign-in like a real relying party.
"""
import base64
import hashlib
import json
import os
import secrets
import struct
import sys
import threading
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from jace_passwords import PORT  # noqa: E402
from jace_passwords.passkeys import b64u, b64u_dec  # noqa: E402
from jace_passwords.server import App, _hash, serve  # noqa: E402
from jace_passwords.vault import Vault, now_iso  # noqa: E402
from test_passkeys import cbor_load  # noqa: E402

SITE_PORT = 47699
TOKEN = secrets.token_urlsafe(24)
state = {"challenge": None, "keys": {}, "log": []}


def setup_vault() -> App:
    v = Vault()
    if not v.exists():
        v.create("test-vault-pass-123", None)
    v.update_device(extensions=[{"id": "e2e", "name": "E2E", "hash": _hash(TOKEN), "createdAt": now_iso()}])
    return App(v)


def app_call(path, body):
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/ext/{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json",
                                          "Origin": "chrome-extension://e2e"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        j = json.loads(e.read() or b"{}")
        return {"error": "locked" if e.code == 423 else "failed", "message": j.get("message")}


class Site(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(ROOT), **k)

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        origin = f"http://localhost:{SITE_PORT}"
        if self.path == "/bg":  # stand-in for background.js
            t = body.get("type")
            if t == "status":
                return self._json(self._status())
            if t == "unlock":
                return self._json(app_call("unlock", {"password": body.get("password", "")}))
            req = body.get("req") or {}
            if t == "passkey-list":
                return self._json(app_call("passkey/list", {"rpId": req.get("rpId", ""), "origin": origin, "allow": req.get("allow", [])}))
            if t in ("passkey-create", "passkey-get"):
                cd = json.dumps({"type": "webauthn.create" if t == "passkey-create" else "webauthn.get",
                                 "challenge": req.get("challenge", ""), "origin": origin, "crossOrigin": False},
                                separators=(",", ":"))
                cdj = b64u(cd.encode())
                if t == "passkey-create":
                    return self._json(app_call("passkey/create", {"rpId": req["rp"]["id"], "origin": origin, "clientDataJSON": cdj,
                                                                   "rpName": req["rp"].get("name", ""), "user": req["user"],
                                                                   "algs": req.get("algs", []), "exclude": req.get("exclude", [])}))
                return self._json(app_call("passkey/get", {"rpId": req["rpId"], "origin": origin, "clientDataJSON": cdj,
                                                            "credentialId": body.get("credentialId")}))
            return self._json({"none": True})
        if self.path == "/challenge":
            state["challenge"] = secrets.token_bytes(32)
            return self._json({"challenge": b64u(state["challenge"])})
        if self.path in ("/verify-register", "/verify-login"):
            try:
                return self._json({"ok": True, "detail": self._verify(body, self.path == "/verify-register", origin)})
            except Exception as e:  # noqa: BLE001
                return self._json({"ok": False, "detail": f"{type(e).__name__}: {e}"})
        self.send_error(404)

    def _status(self):
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}/ext/status",
                                     headers={"Authorization": "Bearer " + TOKEN, "Origin": "chrome-extension://e2e"})
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())

    def _verify(self, cred, register, origin):
        """What a website (relying party) checks."""
        resp = cred["response"]
        cdj = b64u_dec(resp["clientDataJSON"])
        cd = json.loads(cdj)
        assert cd["type"] == ("webauthn.create" if register else "webauthn.get"), cd
        assert cd["challenge"] == b64u(state["challenge"]), "challenge mismatch"
        assert cd["origin"] == origin, cd["origin"]
        rp_hash = hashlib.sha256(b"localhost").digest()
        if register:
            att, _ = cbor_load(b64u_dec(resp["attestationObject"]))
            ad = att["authData"]
            assert ad[:32] == rp_hash and ad[32] & 0x45 == 0x45
            n = struct.unpack(">H", ad[53:55])[0]
            cred_id = ad[55:55 + n]
            assert b64u(cred_id) == cred["id"] == cred["rawId"]
            cose, _ = cbor_load(ad, 55 + n)
            state["keys"][cred["id"]] = (cose[-2], cose[-3])
            return f"registered credential {cred['id'][:10]}… (fmt={att['fmt']}, flags={ad[32]:#x})"
        x, y = state["keys"][cred["id"]]
        pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()).public_key()
        ad = b64u_dec(resp["authenticatorData"])
        assert ad[:32] == rp_hash
        pub.verify(b64u_dec(resp["signature"]), ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return f"signature valid ✓ user handle = {b64u_dec(resp['userHandle']).decode()}"


if __name__ == "__main__":
    app = setup_vault()
    site = ThreadingHTTPServer(("127.0.0.1", SITE_PORT), Site)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    print(f"Site: http://localhost:{SITE_PORT}/tests/passkey-test.html", flush=True)
    serve(app, open_browser=False)
