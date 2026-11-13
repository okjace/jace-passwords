"""Jace Passwords web app: Sign in with Jace + vault sync relay (a Vercel Python function).

The vault is encrypted in the browser; this only ever sees ciphertext. It exists because a
web page can't keep an OAuth client secret or call Jace's sync API across origins.

Routes (vercel.json rewrites /api/jace/<route> here):
  GET  signin    -> redirect to Jace's consent screen (OAuth code flow + PKCE, state in a cookie)
  GET  callback  -> swap the code for a token (with the client secret), keep it in an HttpOnly cookie
  GET  me        -> the signed-in Jace user, or 401
  GET  sync      -> the encrypted vault from Jace's "pw-vault" sync collection
  PUT  sync      -> store it (If-Match: "<version>")
  POST signout   -> forget the token

Environment: JACE_WEB_CLIENT_ID, JACE_WEB_CLIENT_SECRET, SITE_URL (https://…, no slash),
optional JACE_URL (default https://jaceo.vercel.app).
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

JACE_URL = os.environ.get("JACE_URL", "https://jaceo.vercel.app").rstrip("/")
CLIENT_ID = os.environ.get("JACE_WEB_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("JACE_WEB_CLIENT_SECRET", "")
# Unlocking with Jace (vaults without a master password): each account's vault key comes from this
# secret. Made once by packaging/deploy_vercel.py and never changed (changing it locks those vaults).
VAULT_KEY_SECRET = os.environ.get("JP_VAULT_KEY_SECRET", "")
SITE_URL = os.environ.get("SITE_URL", "").rstrip("/")
REDIRECT = f"{SITE_URL}/api/jace/callback"
COLLECTION = "pw-vault"
UA = "JacePasswordsWeb/1.0"
TOKEN_COOKIE, STATE_COOKIE = "jp_jace", "jp_oauth"


def _jace(method, path, token=None, form=None, body=None, headers=None):
    h = {"User-Agent": UA, "Accept": "application/json", **(headers or {})}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(JACE_URL + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=25) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except ValueError:
            return e.code, {"error": str(e)}
    except (urllib.error.URLError, TimeoutError) as e:
        return 502, {"error": "unreachable", "error_description": f"Couldn't reach Jace: {e}"}


def _sign(value: str) -> str:
    mac = hmac.new(CLIENT_SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{value}.{mac}"


def _unsign(signed: str) -> str | None:
    value, _, mac = (signed or "").rpartition(".")
    return value if value and hmac.compare_digest(_sign(value), signed) else None


class handler(BaseHTTPRequestHandler):  # noqa: N801 - Vercel's required name
    def log_message(self, *args):
        pass

    # ---------- plumbing ----------
    def _route(self):
        u = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(u.query)
        route = (q.get("route") or [""])[0]
        if not route and u.path.startswith("/api/jace/"):
            route = u.path[len("/api/jace/"):]
        return route.strip("/"), {k: v[0] for k, v in q.items()}

    def _cookies(self):
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            out[k] = urllib.parse.unquote(v)
        return out

    def _send(self, status, body=None, headers=None, cookies=()):
        data = json.dumps(body if body is not None else {}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location, cookies=()):
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        for c in cookies:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    @staticmethod
    def _cookie(name, value, max_age, path="/api/jace"):
        return (f"{name}={urllib.parse.quote(value)}; Path={path}; Max-Age={int(max_age)}; HttpOnly; Secure; "
                f"SameSite=Lax")

    def _token(self):
        return _unsign(self._cookies().get(TOKEN_COOKIE, ""))

    def _same_site(self):
        """State-changing calls must come from our own page (custom header + Origin check)."""
        if self.headers.get("X-Jace-Passwords") != "1":
            return False
        origin = self.headers.get("Origin")
        return not origin or not SITE_URL or origin == SITE_URL

    def _configured(self):
        if CLIENT_ID and CLIENT_SECRET and SITE_URL:
            return True
        self._send(503, {"error": "not_configured", "error_description": "Sign in with Jace isn't set up on this site yet."})
        return False

    # ---------- routes ----------
    def do_GET(self):  # noqa: N802
        route, q = self._route()
        if route == "signin":
            if not self._configured():
                return
            state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            silent = q.get("prompt") == "none"  # Jace's silent sign-in: no page if you're already signed in
            params = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "scope": "profile sync",
                      "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
            if silent:
                params["prompt"] = "none"
            url = f"{JACE_URL}/oauth/authorize?" + urllib.parse.urlencode(params)
            return self._redirect(url, [self._cookie(STATE_COOKIE, _sign(f"{state}:{verifier}:{int(silent)}"), 600)])
        if route == "callback":
            if not self._configured():
                return
            saved = _unsign(self._cookies().get(STATE_COOKIE, "")) or ""
            state, verifier, silent = (saved.split(":") + ["", "", "0"])[:3]
            clear_state = self._cookie(STATE_COOKIE, "", 0)
            if not state or not hmac.compare_digest(state, q.get("state", "")):
                return self._redirect("/?signin_error=" + urllib.parse.quote("That sign-in didn't match. Please try again."), [clear_state])
            if q.get("error") and silent == "1":
                return self._redirect("/", [clear_state])  # not signed in to Jace (yet): show the button, no error
            if q.get("error"):
                return self._redirect("/?signin_error=" + urllib.parse.quote(q.get("error_description") or q["error"]), [clear_state])
            status, tok = _jace("POST", "/api/oauth/token", form={
                "grant_type": "authorization_code", "code": q.get("code", ""), "redirect_uri": REDIRECT,
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code_verifier": verifier})
            if status != 200 or not tok.get("access_token"):
                msg = tok.get("error_description") or tok.get("error") or "Jace didn't send a sign-in token."
                return self._redirect("/?signin_error=" + urllib.parse.quote(msg), [clear_state])
            max_age = min(int(tok.get("expires_in") or 30 * 86400), 365 * 86400)
            return self._redirect("/", [clear_state, self._cookie(TOKEN_COOKIE, _sign(tok["access_token"]), max_age)])
        if route == "me":
            token = self._token()
            if not token:
                return self._send(401, {"error": "signed_out"})
            status, u = _jace("GET", "/api/oauth/userinfo", token=token)
            if status != 200:
                return self._send(401, {"error": "signed_out"}, cookies=[self._cookie(TOKEN_COOKIE, "", 0)])
            return self._send(200, {"user": {"id": str(u.get("sub") or u.get("id") or ""),
                                             "username": u.get("preferred_username") or u.get("username") or "",
                                             "name": u.get("name") or "", "picture": u.get("picture") or ""}})
        if route == "vault-key":
            return self._vault_key()
        if route == "sync":
            token = self._token()
            if not token:
                return self._send(401, {"error": "signed_out", "error_description": "Sign in with Jace again."})
            status, r = _jace("GET", f"/api/oauth/sync/{COLLECTION}", token=token)
            return self._send(status, r)
        self._send(404, {"error": "not_found"})

    def _vault_key(self):
        """The key that unlocks a vault without a master password, for the signed-in Jace account.
        The web app sends its cookie; the desktop app sends its own Jace token (Bearer). Either way the
        token must be able to use Jace sync (official Jace apps only), not just any app's sign-in."""
        if not VAULT_KEY_SECRET:
            return self._send(503, {"error": "not_configured", "error_description": "Unlocking with Jace isn't set up yet."})
        if self.headers.get("X-Jace-Passwords") != "1":
            return self._send(403, {"error": "forbidden"})
        auth = self.headers.get("Authorization", "")
        token = auth[7:].strip() if auth.startswith("Bearer ") else self._token()
        if not token:
            return self._send(401, {"error": "signed_out", "error_description": "Sign in with Jace first."})
        status, _ = _jace("GET", "/api/oauth/sync", token=token)
        if status != 200:
            return self._send(401, {"error": "invalid_token", "error_description": "Sign in with Jace again."})
        status, u = _jace("GET", "/api/oauth/userinfo", token=token)
        sub = str(u.get("sub") or "") if status == 200 else ""
        if not sub:
            return self._send(401, {"error": "invalid_token", "error_description": "Sign in with Jace again."})
        key = hmac.new(VAULT_KEY_SECRET.encode(), f"jace-passwords vault key v1:{sub}".encode(), hashlib.sha256).digest()
        return self._send(200, {"sub": sub, "key": base64.b64encode(key).decode()})

    def do_PUT(self):  # noqa: N802
        route, _ = self._route()
        if route != "sync":
            return self._send(404, {"error": "not_found"})
        if not self._same_site():
            return self._send(403, {"error": "forbidden"})
        token = self._token()
        if not token:
            return self._send(401, {"error": "signed_out", "error_description": "Sign in with Jace again."})
        n = int(self.headers.get("Content-Length") or 0)
        if n > 12 * 1024 * 1024:
            return self._send(413, {"error": "payload_too_large"})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid_request"})
        status, r = _jace("PUT", f"/api/oauth/sync/{COLLECTION}", token=token,
                          body={"payload": body.get("payload", ""), "device": "Jace Passwords web"},
                          headers={"If-Match": self.headers.get("If-Match", '"0"')})
        self._send(status, r)

    def do_POST(self):  # noqa: N802
        route, _ = self._route()
        if route == "signout" and self._same_site():
            return self._send(200, {"ok": True}, cookies=[self._cookie(TOKEN_COOKIE, "", 0)])
        self._send(404 if route != "signout" else 403, {"error": "not_found"})
