#!/usr/bin/env python3
"""Standalone browser extension, end to end, without installing it.

    python3 tests/ext_standalone_e2e.py   then open http://localhost:47696/tests/ext-standalone.html

Serves the repo, plus the real Jace Passwords site function (webapp/api/jace.py) at /api/jace/*
backed by a fake Jace (one account, token "good", sync kept in memory). A vault that unlocks with
Jace is put on that account first. The page runs extension/background.js with stand-ins for the
browser's extension APIs. /verify checks what the extension synced, with the Python app.
"""
import base64
import hashlib
import hmac
import importlib
import json
import sys
import tempfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "webapp" / "api"))
from jace_passwords import passkeys  # noqa: E402
from jace_passwords.vault import Vault  # noqa: E402

site = importlib.import_module("jace")
SECRET = "test-secret-" + "x" * 40
site.VAULT_KEY_SECRET = SECRET
SUB = "user-1"
SYNC = {"payload": None, "version": 0}


def fake_jace(method, path, token=None, form=None, body=None, headers=None):
    if token != "good":
        return 401, {"error": "invalid_token"}
    if path == "/api/oauth/userinfo":
        return 200, {"sub": SUB, "username": "tester", "name": "Tester"}
    if path == "/api/oauth/sync":
        return 200, {"collections": ["pw-vault"], "records": []}
    if path == "/api/oauth/sync/pw-vault":
        if method == "GET":
            return (404, {"error": "not_found"}) if SYNC["payload"] is None else (200, {"payload": SYNC["payload"], "version": SYNC["version"]})
        want = int((headers or {}).get("If-Match", '"0"').strip('"'))
        if want != SYNC["version"]:
            return 412, {"error": "version_conflict", "version": SYNC["version"]}
        SYNC.update(payload=body["payload"], version=SYNC["version"] + 1)
        return 200, {"version": SYNC["version"]}
    return 404, {"error": "not_found"}


site._jace = fake_jace
JACE_KEY = hmac.new(SECRET.encode(), f"jace-passwords vault key v1:{SUB}".encode(), hashlib.sha256).digest()


def seed():
    v = Vault(Path(tempfile.mkdtemp()))
    v.create(None, {"id": SUB, "username": "tester", "name": "Tester", "picture": ""}, jace_key=JACE_KEY)
    v.create_item({"type": "login", "title": "Example", "fields": {"username": "me@example.com", "password": "Hunter2!x",
                                                                  "urls": ["https://example.com"]}})
    SYNC.update(payload=base64.b64encode(json.dumps(v.file_dict()).encode()).decode(), version=1)


class H(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=str(ROOT), **k)

    def log_message(self, *a):
        pass

    def _site(self):
        site.handler.__dict__  # noqa: B018
        h = site.handler.__new__(site.handler)
        h.__dict__.update(self.__dict__)
        getattr(site.handler, f"do_{self.command}")(h)

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/api/jace/"):
            return self._site()
        if self.path == "/verify":
            f = json.loads(base64.b64decode(SYNC["payload"]))
            v = Vault(Path(tempfile.mkdtemp()))
            v.unlock(None, file=f, jace_key=JACE_KEY)
            items = v.require()["items"]
            pks = [(i, p) for i in items for p in i.get("fields", {}).get("passkeys", [])]
            out = {"version": SYNC["version"], "titles": sorted(i["title"] for i in items if not i.get("purged"))}
            if pks:
                i, p = pks[0]
                origin = "https://login.example.com"
                cd = json.dumps({"type": "webauthn.get", "challenge": "abc", "origin": origin, "crossOrigin": False}).encode()
                a = passkeys.assert_(p, p["rpId"], origin, cd)  # Python signs with the key the extension made
                out["python_can_use_extension_passkey"] = bool(a["signature"])
            b = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b)
            return
        return super().do_GET()

    def do_PUT(self):  # noqa: N802
        return self._site()

    def do_POST(self):  # noqa: N802
        return self._site()


if __name__ == "__main__":
    seed()
    print("http://localhost:47696/tests/ext-standalone.html", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 47696), H).serve_forever()
