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
import re
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
GITHUB_REPO = "okjace/jace-passwords"
EXT_GECKO_ID = "jace-passwords@okjace"
# The browser extension signs in with the browser's own sign-in window (identity.launchWebAuthFlow),
# whose final address is one of these; it gets its token in the URL fragment (never sent anywhere).
# ...and the Jace Passwords phone apps, which get it the same way: Android through a verified App Link (only
# the app signed with the release key opens it: see /.well-known/assetlinks.json), iPhone through Apple's
# sign-in sheet (jacepasswords://auth goes back only to the app that opened the sheet).
EXT_REDIRECT = re.compile(r"^(https://[a-z0-9-]+\.(chromiumapp\.org|extensions\.allizom\.org)/[A-Za-z0-9/_-]*"
                          r"|https://jace-passwords\.vercel\.app/(android-auth|ext-auth)|jacepasswords://auth)$")
APP_STATE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")  # the app's own check value, echoed back with the token


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
        if "Cache-Control" not in (headers or {}):
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

    def _bearer(self):
        auth = self.headers.get("Authorization", "")
        return auth[7:].strip() if auth.startswith("Bearer ") else None

    def _token(self):
        """The web app's cookie, or the extension's own token (Authorization: Bearer)."""
        return self._bearer() or _unsign(self._cookies().get(TOKEN_COOKIE, ""))

    def _same_site(self):
        """State-changing calls must come from our own page (custom header + Origin check)."""
        if self.headers.get("X-Jace-Passwords") != "1":
            return False
        if self._bearer():  # the extension: no cookie involved, so no cross-site forgery to stop
            return True
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
            ext = q.get("ext_redirect", "")
            if ext and not EXT_REDIRECT.match(ext):
                return self._send(400, {"error": "invalid_request", "error_description": "Unknown extension address."})
            app_state = q.get("app_state", "")
            if app_state and not APP_STATE.match(app_state):
                return self._send(400, {"error": "invalid_request", "error_description": "Bad app_state."})
            params = {"response_type": "code", "client_id": CLIENT_ID, "redirect_uri": REDIRECT, "scope": "profile sync",
                      "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
            # Always show Jace's "allow Jace Passwords to use your account?" page when you press Sign in: Jace
            # would otherwise approve Jace's own apps by itself in Jace Browser. (prompt=none: never a page.)
            params["prompt"] = "none" if silent else "consent"
            url = f"{JACE_URL}/oauth/authorize?" + urllib.parse.urlencode(params)
            ext_b64 = base64.urlsafe_b64encode(ext.encode()).decode().rstrip("=")
            return self._redirect(url, [self._cookie(STATE_COOKIE, _sign(f"{state}:{verifier}:{int(silent)}:{ext_b64}:{app_state}"), 600)])
        if route == "callback":
            if not self._configured():
                return
            saved = _unsign(self._cookies().get(STATE_COOKIE, "")) or ""
            state, verifier, silent, ext_b64, app_state = (saved.split(":") + ["", "", "0", "", ""])[:5]
            ext = base64.urlsafe_b64decode(ext_b64 + "=" * (-len(ext_b64) % 4)).decode() if ext_b64 else ""
            if ext and not EXT_REDIRECT.match(ext):
                ext = ""
            clear_state = self._cookie(STATE_COOKIE, "", 0)
            if not state or not hmac.compare_digest(state, q.get("state", "")):
                return self._redirect("/app?signin_error=" + urllib.parse.quote("That sign-in didn't match. Please try again."), [clear_state])
            if q.get("error") and silent == "1":
                return self._redirect("/app", [clear_state])  # not signed in to Jace (yet): show the button, no error
            if q.get("error"):
                return self._redirect("/app?signin_error=" + urllib.parse.quote(q.get("error_description") or q["error"]), [clear_state])
            status, tok = _jace("POST", "/api/oauth/token", form={
                "grant_type": "authorization_code", "code": q.get("code", ""), "redirect_uri": REDIRECT,
                "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code_verifier": verifier})
            if status != 200 or not tok.get("access_token"):
                msg = tok.get("error_description") or tok.get("error") or "Jace didn't send a sign-in token."
                return self._redirect("/app?signin_error=" + urllib.parse.quote(msg), [clear_state])
            max_age = min(int(tok.get("expires_in") or 30 * 86400), 365 * 86400)
            if ext:  # back to the extension's sign-in window: the token travels in the fragment only
                frag = urllib.parse.urlencode({"token": tok["access_token"], "expires_in": max_age,
                                               **({"app_state": app_state} if app_state else {})})
                return self._redirect(f"{ext}#{frag}", [clear_state])
            return self._redirect("/app", [clear_state, self._cookie(TOKEN_COOKIE, _sign(tok["access_token"]), max_age)])
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
        if route in ("ext-updates", "ext-latest"):  # the browser extension's updates, from GitHub releases
            return self._ext_updates(route)
        if route == "altstore":  # the iPhone app's AltStore / SideStore source, from GitHub releases
            return self._altstore()
        if route == "breaches":  # Have I Been Pwned's breached websites, for Watchtower (its API has no CORS)
            return self._breaches()
        if route == "vault-key":
            return self._vault_key()
        if route == "field-rules":  # everyone's field reports (Jace keeps them), downloaded whole: no per-site lookups
            return self._field_rules()
        if route == "sync":
            token = self._token()
            if not token:
                return self._send(401, {"error": "signed_out", "error_description": "Sign in with Jace again."})
            status, r = _jace("GET", f"/api/oauth/sync/{COLLECTION}", token=token)
            return self._send(status, r)
        self._send(404, {"error": "not_found"})

    _release_cache = {"at": 0, "data": None}

    @staticmethod
    def _load_releases() -> bool:
        """GitHub releases (cached 15 minutes): the signed extensions and the iPhone apps. False if unreachable."""
        c = handler._release_cache
        if not c["data"] or c["at"] < time.time() - 900:
            req = urllib.request.Request(f"https://api.github.com/repos/{GITHUB_REPO}/releases?per_page=30",
                                         headers={"User-Agent": UA, "Accept": "application/vnd.github+json"})
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    releases = json.loads(r.read())
            except (urllib.error.URLError, TimeoutError, ValueError):
                if not c["data"]:
                    return False
                releases = None
            if releases is not None:
                found = []
                ipas = []
                for rel in releases:
                    if rel.get("draft") or rel.get("prerelease"):
                        continue
                    for a in rel.get("assets", []):
                        m = re.fullmatch(r"JacePasswords-(\d+\.\d+\.\d+)-ios\.ipa", a.get("name", ""))
                        if m:
                            ipas.append({"version": m.group(1), "date": rel.get("published_at") or "", "downloadURL": a["browser_download_url"],
                                         "size": a.get("size") or 0, "localizedDescription": (rel.get("body") or "").split("\n---")[0][:4000],
                                         "minOSVersion": "16.0"})
                    assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
                    for name, url in assets.items():
                        m = re.fullmatch(r"jace-passwords-(\d+\.\d+\.\d+)-signed\.xpi", name)
                        if m:
                            chrome = assets.get(f"jace-passwords-{m.group(1)}-chrome.zip")
                            found.append({"version": m.group(1), "xpi": url, "chrome": chrome, "page": rel.get("html_url")})
                uniq = {f["version"]: f for f in found}
                c.update(at=time.time(), data=sorted(uniq.values(), key=lambda f: tuple(int(x) for x in f["version"].split("."))), ipas=ipas)
        return True

    def _ext_updates(self, route):
        """ext-updates: Firefox's update manifest (gecko update_url), so Jace Browser and Firefox update the
        signed extension by themselves. ext-latest: the newest version, for copies that can't update."""
        if not handler._load_releases():
            return self._send(502, {"error": "unreachable"})
        versions = handler._release_cache["data"] or []
        if route == "ext-latest":
            return self._send(200, versions[-1] if versions else {}, headers={"Cache-Control": "public, max-age=900"})
        return self._send(200, {"addons": {EXT_GECKO_ID: {"updates": [
            {"version": v["version"], "update_link": v["xpi"]} for v in versions]}}},
            headers={"Cache-Control": "public, max-age=900"})

    def _altstore(self):
        """AltStore / SideStore source (their "apps.json" format): add it once and they keep the app updated."""
        if not handler._load_releases():
            return self._send(502, {"error": "unreachable"})
        versions = handler._release_cache.get("ipas") or []
        site = SITE_URL or "https://jace-passwords.vercel.app"
        return self._send(200, {
            "name": "Jace Passwords", "identifier": "com.okjace.jacepasswords.source", "website": site,
            "subtitle": "Passwords, passkeys, 2FA codes and cards", "iconURL": f"{site}/img/app-icon.png", "tintColor": "3ddc84",
            "apps": [{
                "name": "Jace Passwords", "bundleIdentifier": "com.okjace.jacepasswords", "developerName": "okjace",
                "subtitle": "Your passwords, passkeys and 2FA codes, end-to-end encrypted.",
                "localizedDescription": "Jace Passwords keeps your logins, passkeys, 2FA codes (including Steam Guard), cards and addresses "
                                        "end-to-end encrypted and synced with your Jace account. Autofill works in Safari through the "
                                        "Jace Passwords Safari extension.",
                "iconURL": f"{site}/img/app-icon.png", "tintColor": "3ddc84", "category": "utilities",
                "screenshots": [f"{site}/img/vault.png"],
                "versions": versions,
                "appPermissions": {"entitlements": [], "privacy": {}},
            }],
            "news": [],
        }, headers={"Cache-Control": "public, max-age=900"})

    _breach_cache = {"at": 0, "data": None}

    def _breaches(self):
        c = handler._breach_cache
        if not c["data"] or c["at"] < time.time() - 21600:
            req = urllib.request.Request("https://haveibeenpwned.com/api/v3/breaches",
                                         headers={"User-Agent": UA, "Accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=25) as r:
                    raw = json.loads(r.read())
            except (urllib.error.URLError, TimeoutError, ValueError):
                return self._send(502, {"error": "unreachable"}) if not c["data"] else self._send(200, c["data"])
            out = {}
            for b in raw:
                d = (b.get("Domain") or "").lower()
                if not d or b.get("IsSpamList") or b.get("IsFabricated") or b.get("IsRetired"):
                    continue
                out.setdefault(d, []).append({"name": b.get("Title") or b.get("Name"), "date": b.get("BreachDate") or "",
                                              "added": b.get("AddedDate") or "", "count": b.get("PwnCount") or 0,
                                              "passwords": "Passwords" in (b.get("DataClasses") or [])})
            c.update(at=time.time(), data=out)
        return self._send(200, c["data"], headers={"Cache-Control": "public, max-age=21600"})

    def _vault_key(self):
        """The key that unlocks a vault without a master password, for the signed-in Jace account.
        The web app sends its cookie; the desktop app sends its own Jace token (Bearer). Either way the
        token must be able to use Jace sync (official Jace apps only), not just any app's sign-in."""
        if not VAULT_KEY_SECRET:
            return self._send(503, {"error": "not_configured", "error_description": "Unlocking with Jace isn't set up yet."})
        if self.headers.get("X-Jace-Passwords") != "1":
            return self._send(403, {"error": "forbidden"})
        token = self._token()
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

    _rules_cache = {"at": 0, "data": None}

    def _field_rules(self):
        c = handler._rules_cache
        if not c["data"] or c["at"] < time.time() - 300:
            status, r = _jace("GET", "/api/oauth/passwords/field-rules")
            if status == 200 and isinstance(r.get("rules"), dict):
                c.update(at=time.time(), data=r)
            elif not c["data"]:
                return self._send(502, {"error": "unreachable", "rules": {}})
        return self._send(200, c["data"], headers={"Cache-Control": "public, max-age=300"})

    def do_POST(self):  # noqa: N802
        route, _ = self._route()
        if route == "field-rules":  # report a field: "this is the password / email / … field"
            if not self._same_site():
                return self._send(403, {"error": "forbidden"})
            token = self._token()
            if not token:
                return self._send(401, {"error": "signed_out", "error_description": "Sign in with Jace to report fields."})
            n = int(self.headers.get("Content-Length") or 0)
            try:
                body = json.loads(self.rfile.read(min(n, 4096)) or b"{}")
            except ValueError:
                return self._send(400, {"error": "invalid_request"})
            status, r = _jace("POST", "/api/oauth/passwords/field-rules", token=token,
                              body={k: body.get(k) for k in ("host", "field", "kind")})
            if status == 200:
                handler._rules_cache["at"] = 0  # show it in the next download
            return self._send(status, r)
        if route == "signout" and self._same_site():
            return self._send(200, {"ok": True}, cookies=[self._cookie(TOKEN_COOKIE, "", 0)])
        self._send(404 if route != "signout" else 403, {"error": "not_found"})
