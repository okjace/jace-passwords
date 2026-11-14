"""The local Jace Passwords server (127.0.0.1 only).

Two kinds of callers:
  * the app window (web/), with a session cookie it got from a launch link only
    you can read (data_dir/server.json), plus an X-Jace-Passwords header on every
    API call so other web pages can't forge requests;
  * the browser extension (extension/), with a Bearer token it got by pairing
    with a 6-digit code shown in the app.
"""
import hashlib
import hmac
import html
import json
import mimetypes
import secrets
import socket
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import APP_NAME, APP_VERSION, CLIENT_ID, HOST, PORT, WEB_URL, crypto, jaceos, net, generator, importers, jace, passkeys, security, totp, write_private
from .vault import ITEM_TYPES, Locked, Vault, VaultError, new_id, now_iso

WEB = Path(__file__).parent / "web"
ALLOWED_HOSTS = {f"{HOST}:{PORT}", f"localhost:{PORT}"}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class ApiError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


class App:
    def __init__(self, vault: Vault | None = None):
        self.vault = vault or Vault()
        self.sessions: set[str] = set()
        self.launch_key = secrets.token_urlsafe(32)
        self.auth = jace.Auth()
        self.pairing: dict | None = None
        self.sync_state = {"status": "idle", "at": None, "error": None, "version": 0}
        self._sync_timer: threading.Timer | None = None
        self._sync_lock = threading.Lock()
        self.signin_error: str | None = None
        self.on_show = None  # the desktop app sets this to raise its window
        dev = self.vault.device()
        self.sync_state["version"] = int(dev.get("syncVersion", 0))

    # ---------- Jace account ----------
    def jace_account(self) -> dict | None:
        acct = self.vault.device().get("jace")
        if not acct:
            return None
        if acct.get("expires_at") and acct["expires_at"] < time.time():
            return None
        return acct

    def public_account(self):
        a = self.jace_account()
        return jace.public_user(a["user"]) if a else None

    def sign_in_with_jace_os(self) -> bool:
        """Jace OS: sign in with the computer's Jace account, without asking (like Jace Social)."""
        if not jaceos.available():
            return False
        got = jaceos.token_for(CLIENT_ID, "profile sync")
        if not got:
            return False
        try:
            acct = jace.account_from_token(got["access_token"], got.get("expires_in"), got.get("scope", ""))
        except jace.JaceError:
            return False
        self.vault.update_device(jace=acct)
        self.signin_error = None
        if self.vault.unlocked:
            self.vault.set_account(jace.public_user(acct["user"]))
            self.schedule_sync(0.1)
        return True

    def jace_key(self) -> bytes:
        """The key for a vault unlocked with Jace (no master password), from the Jace Passwords site."""
        acct = self.jace_account()
        if not acct:
            raise ApiError("Sign in with Jace to unlock this vault.")
        req = urllib.request.Request(f"{WEB_URL}/api/jace/vault-key", headers={
            "Authorization": f"Bearer {acct['access_token']}", "X-Jace-Passwords": "1", "Accept": "application/json",
            "User-Agent": f"JacePasswords/{APP_VERSION}"})
        try:
            with net.urlopen(req, timeout=20) as r:
                body = json.loads(r.read())
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read()).get("error_description")
            except ValueError:
                msg = None
            raise ApiError(msg or f"Couldn't get your vault key from Jace Passwords ({e.code}).")
        except (urllib.error.URLError, OSError) as e:
            raise ApiError("Couldn't reach Jace Passwords to unlock with Jace. Check your internet connection.") from e
        mine = str(jace.public_user(acct["user"])["id"])
        if body.get("sub") != mine:
            raise ApiError("That key is for a different Jace account.")
        return crypto.b64d(body["key"])

    def unlock_vault(self, password=None, secret_key=None):
        v = self.vault
        if v.key_mode() == "device":
            v.unlock(None)
        elif v.key_mode() == "jace":
            owner = (v.read_file().get("kdf") or {}).get("sub")
            acct = self.public_account()
            if acct and owner and acct["id"] != owner:
                raise ApiError("This vault belongs to another Jace account. Sign in with that one.")
            v.unlock(None, jace_key=self.jace_key())
        else:
            v.unlock(password or "", secret_key or None)
        self.schedule_sync(0.1)

    def auto_sign_in(self):
        """At startup: on Jace OS, sign in silently if this computer is signed in to Jace; then open a
        vault that has no master password."""
        def run():
            if not self.jace_account() and jaceos.available():
                self.sign_in_with_jace_os()
            self.auto_open()
        threading.Thread(target=run, daemon=True).start()

    def auto_open(self):
        v = self.vault
        if not v.exists() or v.unlocked:
            return
        mode = v.key_mode()
        if mode == "device" or (mode == "jace" and self.jace_account()) or (mode == "password" and v.remembered()):
            try:
                self.unlock_vault()
            except Exception:  # noqa: BLE001 - offline etc.: the lock screen has a button
                pass

    def adopt_jace_key(self):
        """A device-only vault that starts syncing moves to the Jace key, so your other devices can open it."""
        v = self.vault
        if v.unlocked and v.key_mode() == "device" and self.jace_account():
            v.set_key_mode("jace", jace_key=self.jace_key())

    # ---------- sync ----------
    def schedule_sync(self, delay=2.0):
        if not self.jace_account() or not self.vault.unlocked:
            return
        if self._sync_timer:
            self._sync_timer.cancel()
        self._sync_timer = threading.Timer(delay, self.sync_now)
        self._sync_timer.daemon = True
        self._sync_timer.start()

    def sync_now(self) -> dict:
        acct = self.jace_account()
        if not acct or not self.vault.unlocked:
            return self.sync_state
        with self._sync_lock:
            self.sync_state.update(status="syncing", error=None)
            try:
                token = acct["access_token"]
                self.adopt_jace_key()
                for _ in range(4):
                    remote, version = jace.pull(token)
                    if remote:
                        self.vault.merge_remote(remote)
                    try:
                        new_version = jace.push(token, self.vault.file_dict(), version, socket.gethostname()[:60])
                        break
                    except jace.Conflict:
                        continue
                else:
                    raise jace.JaceError("Couldn't sync: another device kept changing the vault. Try again.")
                self.vault.update_device(syncVersion=new_version)
                self.sync_state.update(status="synced", at=now_iso(), version=new_version)
            except (jace.JaceError, VaultError) as e:
                self.sync_state.update(status="error", error=str(e))
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                self.sync_state.update(status="error", error=f"Sync failed: {e}")
        return self.sync_state

    def after_change(self):
        self.schedule_sync()

    # ---------- auto-lock ----------
    def autolock_loop(self):
        while True:
            time.sleep(10)
            v = self.vault
            if v.unlocked:
                minutes = v.settings().get("autoLockMinutes", 10)
                if minutes and v.key_mode() != "device" and not v.remembered() and time.time() - v.last_activity > float(minutes) * 60:
                    v.lock()

    # ---------- state ----------
    def state(self) -> dict:
        v = self.vault
        acct = v.account() if v.exists() else None
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "setup": v.exists(),
            "locked": not v.unlocked,
            "hasSecretKey": bool(v.device().get("secretKey")),
            "usesSecretKey": v.uses_secret_key() if v.exists() else None,
            "keyMode": v.key_mode() if v.exists() else None,
            "remembered": v.remembered() if v.exists() else False,
            "needsSecretKey": bool(v.exists() and v.uses_secret_key() and not v.device().get("secretKey")),
            "jace": self.public_account(),
            "vaultAccount": acct,
            "sync": self.sync_state,
            "signinError": self.signin_error,
            "settings": v.settings() if v.unlocked else None,
        }


def item_summary(i: dict) -> dict:
    f = i.get("fields", {})
    s = {"id": i["id"], "type": i["type"], "title": i.get("title", ""), "vaultId": i.get("vaultId"),
         "favorite": i.get("favorite", False)}
    if i["type"] == "login":
        s.update(username=f.get("username", ""), urls=f.get("urls") or [], hasTotp=bool(f.get("totp")),
                 signInWith=f.get("signInWith"), hasPassword=bool(f.get("password")),
                 passkeys=len(f.get("passkeys") or []))
    elif i["type"] == "card":
        num = "".join(c for c in (f.get("number") or "") if c.isdigit())
        s.update(last4=num[-4:], brand=f.get("brand") or card_brand(num), cardType=f.get("cardType", "credit"),
                 cardholder=f.get("cardholder", ""))
    elif i["type"] == "identity":
        s.update(name=f.get("fullName", ""), email=f.get("email", ""))
    elif i["type"] == "alias":
        s.update(alias=f.get("alias", ""))
    return s


def _norm(s) -> str:
    return " ".join("".join(c.lower() if c.isalnum() else " " for c in str(s or "")).split())


def _item_title(kind: str, f: dict) -> tuple[str, str]:
    if kind == "card":
        num = "".join(c for c in f.get("number", "") if c.isdigit())
        brand = card_brand(num) or "Card"
        exp = f"{f.get('expMonth', '')}/{str(f.get('expYear', ''))[-2:]}" if f.get("expMonth") else ""
        return f"{brand} •••• {num[-4:]}", " · ".join(x for x in (f"{brand} •••• {num[-4:]}", f.get("cardholder", ""), f"expires {exp}" if exp else "") if x)
    name = f.get("fullName") or " ".join(x for x in (f.get("firstName"), f.get("lastName")) if x)
    place = ", ".join(x for x in (f.get("address1"), f.get("city"), f.get("state"), f.get("zip")) if x)
    title = name or f.get("email") or f.get("address1") or "Address"
    return title, " · ".join(x for x in (name, place, f.get("email", ""), f.get("phone", "")) if x)


def _find_same(v, kind: str, f: dict):
    """The card with the same number, or the identity with the same street address (or email)."""
    for i in v.visible_items():
        if i["type"] != kind:
            continue
        g = i.get("fields", {})
        if kind == "card":
            if f.get("number") and "".join(c for c in g.get("number", "") if c.isdigit()) == "".join(c for c in f["number"] if c.isdigit()):
                return i
        elif f.get("address1"):
            if _norm(g.get("address1")) == _norm(f["address1"]):
                return i
        elif f.get("email") and _norm(g.get("email")) == _norm(f["email"]):
            return i
    return None


def card_brand(num: str) -> str:
    if num.startswith("4"):
        return "Visa"
    if num[:2] in ("51", "52", "53", "54", "55") or (num[:4].isdigit() and 2221 <= int(num[:4] or 0) <= 2720):
        return "Mastercard"
    if num[:2] in ("34", "37"):
        return "Amex"
    if num.startswith(("6011", "65")) or num[:3] in ("644", "645", "646", "647", "648", "649"):
        return "Discover"
    if num[:4].isdigit() and 3528 <= int(num[:4]) <= 3589:
        return "JCB"
    if num.startswith(("36", "300", "301", "302", "303", "304", "305", "38")):
        return "Diners"
    if num.startswith(("50", "56", "57", "58", "6")):
        return "Maestro"
    return ""


def luhn_ok(num: str) -> bool:
    d = [int(c) for c in num if c.isdigit()]
    if len(d) < 12:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"JacePasswords/{APP_VERSION}"
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        # ---------- plumbing ----------
        def _origin_ok_for_ext(self):
            o = self.headers.get("Origin", "")
            return o.startswith(("chrome-extension://", "moz-extension://", "safari-web-extension://"))

        def _send(self, status, body=b"", ctype="application/json", headers=None):
            if isinstance(body, (dict, list)):
                body = json.dumps(body).encode()
            elif isinstance(body, str):
                body = body.encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            if ctype.startswith("text/html"):
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy",
                                 "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; "
                                 "connect-src 'self'; frame-ancestors 'none'")
            if self.path.startswith("/ext/") and self._origin_ok_for_ext():
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Vary", "Origin")
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json_body(self) -> dict:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 20 * 1024 * 1024:
                raise ApiError("Too large.", 413)
            raw = self.rfile.read(n) if n else b""
            if not raw:
                return {}
            try:
                body = json.loads(raw)
            except ValueError:
                raise ApiError("Bad JSON.")
            if not isinstance(body, dict):
                raise ApiError("Bad JSON.")
            return body

        def _cookie_session(self):
            for part in (self.headers.get("Cookie") or "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == "jp_session" and v in app.sessions:
                    return v
            return None

        def _ext_token(self):
            h = self.headers.get("Authorization", "")
            if not h.startswith("Bearer "):
                return None
            th = _hash(h[7:].strip())
            for e in app.vault.device().get("extensions", []):
                if hmac.compare_digest(e["hash"], th):
                    return e
            return None

        def do_OPTIONS(self):  # noqa: N802
            if self.path.startswith("/ext/") and self._origin_ok_for_ext():
                self._send(204, b"", headers={
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Authorization, Content-Type",
                    "Access-Control-Max-Age": "600"})
            else:
                self._send(403, {"error": "forbidden"})

        def do_GET(self):  # noqa: N802
            self._dispatch("GET")

        def do_HEAD(self):  # noqa: N802
            self._dispatch("GET")

        def do_POST(self):  # noqa: N802
            self._dispatch("POST")

        def do_PUT(self):  # noqa: N802
            self._dispatch("PUT")

        def do_DELETE(self):  # noqa: N802
            self._dispatch("DELETE")

        def _dispatch(self, method):
            # DNS-rebinding guard: only answer to our own address.
            if self.headers.get("Host", "") not in ALLOWED_HOSTS:
                return self._send(421, {"error": "wrong host"})
            url = urllib.parse.urlparse(self.path)
            path, query = url.path, {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
            try:
                if path.startswith("/api/"):
                    if not self._cookie_session() or self.headers.get("X-Jace-Passwords") != "1":
                        raise ApiError("Open Jace Passwords from its app.", 401)
                    before = app.vault.last_activity
                    result = api(method, path[5:], query, self._json_body() if method != "GET" else {})
                    if self.headers.get("X-Background") == "1":
                        app.vault.last_activity = before  # polling isn't you using the app
                    return self._send(200, result)
                if path.startswith("/ext/"):
                    return self._send(200, ext_api(self, method, path[5:], query,
                                                   self._json_body() if method != "GET" else {}))
                if path == "/jace/callback":
                    return self._callback(query)
                if path == "/app/show" and method == "POST":
                    if not hmac.compare_digest(str(self._json_body().get("key", "")), app.launch_key):
                        raise ApiError("Not allowed.", 403)
                    if app.on_show:
                        app.on_show()
                    return self._send(200, {"ok": True})
                return self._static(path, query)
            except Locked as e:
                self._send(423, {"error": "locked", "message": str(e)})
            except (ApiError, VaultError, crypto.CryptoError, jace.JaceError, ValueError) as e:
                self._send(getattr(e, "status", 400), {"error": "bad_request", "message": str(e)})
            except Exception as e:  # noqa: BLE001
                traceback.print_exc()
                self._send(500, {"error": "server", "message": f"Something went wrong: {e}"})

        def _callback(self, query):
            try:
                acct = app.auth.finish(query)
                app.vault.update_device(jace=acct)
                app.signin_error = None
                if app.vault.unlocked:
                    app.vault.set_account(jace.public_user(acct["user"]))
                    app.schedule_sync(0.1)
            except jace.JaceError as e:
                app.signin_error = str(e)
            if not self._cookie_session():  # finished in another browser: the app window picks it up
                ok = not app.signin_error
                return self._send(200, SIGNED_IN.format(title="Signed in to Jace" if ok else "Sign-in didn't work",
                                                        text="You can close this tab and go back to Jace Passwords."
                                                        if ok else html.escape(app.signin_error or "")),
                                  "text/html; charset=utf-8")
            self._send(302, b"", headers={"Location": "/"})

        def _static(self, path, query):
            if path == "/" and query.get("launch"):
                if not hmac.compare_digest(query["launch"], app.launch_key):
                    return self._send(403, "Not allowed", "text/plain")
                sid = secrets.token_urlsafe(32)
                app.sessions.add(sid)
                return self._send(302, b"", headers={
                    "Location": "/",
                    "Set-Cookie": f"jp_session={sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=2592000"})
            if path in ("/", "/index.html"):
                if not self._cookie_session():
                    return self._send(200, NOT_LAUNCHED, "text/html; charset=utf-8")
                path = "/index.html"
            f = (WEB / path.lstrip("/")).resolve()
            if WEB.resolve() not in f.parents or not f.is_file():
                return self._send(404, "Not found", "text/plain")
            ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript",):
                ctype += "; charset=utf-8"
            self._send(200, f.read_bytes(), ctype)

    # ---------- the app's API ----------
    def api(method, route, q, body):
        v = app.vault
        parts = route.strip("/").split("/")
        head = parts[0]
        arg = parts[1] if len(parts) > 1 else None
        sub = parts[2] if len(parts) > 2 else None

        if head == "state":
            return app.state()

        if head == "jace":
            if arg == "signin":
                app.signin_error = None
                if app.sign_in_with_jace_os():
                    return {"signedIn": True}
                return {"url": app.auth.start()}
            if arg == "signout":
                v.update_device(jace=None)
                app.sync_state.update(status="idle", error=None)
                return {"ok": True}
            if arg == "remote":
                acct = app.jace_account()
                if not acct:
                    raise ApiError("Sign in with Jace first.")
                remote, version = jace.pull(acct["access_token"])
                return {"exists": bool(remote), "account": (remote or {}).get("account"),
                        "usesSecretKey": Vault.file_uses_secret_key(remote) if remote else False,
                        "keyMode": Vault.file_key_mode(remote) if remote else None}

        if head == "setup":
            if v.exists():
                raise ApiError("A vault already exists on this computer.")
            acct = app.public_account()
            if body.get("mode") == "restore":
                a = app.jace_account()
                if not a:
                    raise ApiError("Sign in with Jace first.")
                remote, version = jace.pull(a["access_token"])
                if not remote:
                    raise ApiError("There's no vault on your Jace account yet.")
                if Vault.file_key_mode(remote) == "jace":
                    v.unlock(None, file=remote, jace_key=app.jace_key())
                else:
                    v.unlock(body.get("password", ""), body.get("secretKey", ""), file=remote)
                v.update_device(syncVersion=version)
                app.sync_state["version"] = version
                return {"ok": True}
            # Linked to Jace: no Secret Key (your Jace sign-in guards the synced copy instead).
            if body.get("skipPassword"):  # no master password: the Jace key if linked, else this device's
                v.create(None, acct, jace_key=app.jace_key() if acct else None)
                app.schedule_sync(0.1)
                return {"secretKey": None}
            sk = v.create(body.get("password", ""), acct, use_secret_key=acct is None)
            app.schedule_sync(0.1)
            return {"secretKey": sk}

        if head == "unlock":
            app.unlock_vault(body.get("password"), body.get("secretKey"))
            return {"ok": True}

        if head == "ping":
            if v.unlocked:
                v.touch()
            return {"ok": True}

        if head == "lock":
            v.lock()
            return {"ok": True}

        if head == "sync":
            return app.sync_now()

        if head == "generate":
            pw = generator.generate(body)
            return {"password": pw, "strength": generator.strength(pw)}

        if head == "strength":
            return generator.strength(body.get("password", ""))

        if head == "totp" and arg == "parse":
            return totp.parse(body.get("value", ""))

        if head == "card-check":
            num = "".join(c for c in body.get("number", "") if c.isdigit())
            return {"brand": card_brand(num), "valid": luhn_ok(num)}

        # ---- everything below needs the vault unlocked ----
        data = v.require()

        if head == "vault":
            return v.snapshot()

        if head == "items":
            if method == "POST" and not arg:
                it = v.create_item(body)
                app.after_change()
                return it
            if not arg:
                return v.visible_items(include_trash=True)
            if method == "PUT":
                it = v.update_item(arg, body)
                app.after_change()
                return it
            if method == "DELETE":
                v.purge_item(arg) if q.get("purge") else v.trash_item(arg)
                app.after_change()
                return {"ok": True}
            if method == "POST" and sub == "restore":
                v.restore_item(arg)
                app.after_change()
                return {"ok": True}
            if method == "POST" and sub == "used":
                v.mark_used(arg)
                return {"ok": True}
            if sub == "totp":
                return totp.code(v.get_item(arg).get("fields", {}).get("totp", ""))
            return v.get_item(arg)

        if head == "trash" and method == "DELETE":
            n = v.empty_trash()
            app.after_change()
            return {"purged": n}

        if head == "vaults":
            if method == "POST":
                r = v.create_vault(body)
            elif method == "PUT":
                r = v.update_vault(arg, body)
            elif method == "DELETE":
                v.delete_vault(arg)
                r = {"ok": True}
            else:
                return data["vaults"]
            app.after_change()
            return r

        if head == "settings":
            s = v.update_settings(body)
            app.after_change()
            return s

        if head == "generator-history":
            if method == "POST":
                v.remember_generated(body.get("password", ""))
                return {"ok": True}
            return data.get("generatorHistory", [])

        if head == "totp-codes":
            out = {}
            for i in v.visible_items():
                t = i.get("fields", {}).get("totp")
                if t:
                    try:
                        out[i["id"]] = totp.code(t)
                    except ValueError:
                        pass
            return out

        if head == "watchtower":
            if arg == "breach":
                results = {}
                checked = {}
                for i in v.visible_items():
                    pw = i.get("fields", {}).get("password") if i["type"] == "login" else None
                    if not pw:
                        continue
                    if pw not in checked:
                        try:
                            checked[pw] = security.pwned_count(pw)
                        except Exception:  # noqa: BLE001
                            raise ApiError("Couldn't reach Have I Been Pwned. Check your connection.")
                    if checked[pw]:
                        results[i["id"]] = checked[pw]
                return {"breached": results, "checkedAt": now_iso()}
            return security.report(v.visible_items(), security.watchtower_data())

        if head == "alias":
            base = (body.get("base") or v.settings().get("aliasBase") or "").strip()
            if "@" not in base:
                raise ApiError("Set the email your aliases forward to first (Settings → Email aliases).")
            user, domain = base.split("@", 1)
            tag = "".join(c for c in (body.get("site") or "") .lower() if c.isalnum())[:20] or secrets.token_hex(3)
            return {"alias": f"{user.split('+')[0]}+{tag}.{secrets.token_hex(2)}@{domain}", "forwardsTo": base}

        if head == "import":
            items = importers.parse_csv(body.get("csv", ""))
            vault_id = body.get("vaultId")
            for it in items:
                it["vaultId"] = vault_id
                v.create_item(it)
            app.after_change()
            return {"imported": len(items)}

        if head == "import-items" and method == "POST":  # parsed in the app window (web/import.js)
            r = v.import_items(body.get("items") or [], body.get("vaultId"))
            app.after_change()
            return r

        if head == "passkey-move" and method == "POST":  # link a passkey to another login
            it = v.move_passkey(body.get("fromId", ""), body.get("credentialId", ""), body.get("toId", ""))
            app.after_change()
            return {"ok": True, "id": it["id"]}

        if head == "export":
            if not v.verify_password(body.get("password", "")):
                raise ApiError("That master password is wrong.", 403)
            items = v.visible_items()
            if body.get("format") == "csv":
                return {"filename": "jace-passwords.csv", "content": importers.to_csv(items), "mime": "text/csv"}
            return {"filename": "jace-passwords-backup.json", "mime": "application/json",
                    "content": json.dumps(v.file_dict(), indent=1)}

        if head == "key-mode" and method == "POST":  # master password <-> unlock with Jace
            mode = body.get("mode")
            v.set_key_mode(mode, password=body.get("password"), current=body.get("current"),
                           jace_key=app.jace_key() if mode == "jace" else None)
            app.after_change()
            return {"ok": True}

        if head == "password":
            if v.key_mode() in ("jace", "device"):
                v.set_key_mode("password", password=body.get("new", ""))
            else:
                v.change_password(body.get("current", ""), body.get("new", ""))
            app.after_change()
            return {"ok": True}

        if head == "remember" and method == "POST":  # open on this device without the master password
            v.remember(bool(body.get("on")), body.get("password", ""))
            return {"ok": True, "remembered": v.remembered()}

        if head == "secret-key" and method == "POST":
            use = bool(body.get("use"))
            if not use and not app.jace_account():
                raise ApiError("Sign in with Jace first: without a Secret Key, your Jace account protects the synced copy.")
            sk = v.set_secret_key(body.get("password", ""), use)
            app.after_change()
            return {"secretKey": sk}

        if head == "emergency-kit":
            if not v.verify_password(body.get("password", "")):
                raise ApiError("That master password is wrong.", 403)
            return {"secretKey": v.device().get("secretKey", ""), "account": app.public_account(),
                    "jaceUrl": jace.JACE_URL}

        if head == "devices":
            exts = v.device().get("extensions", [])
            if method == "DELETE":
                v.update_device(extensions=[e for e in exts if e["id"] != arg])
                return {"ok": True}
            return [{k: e[k] for k in ("id", "name", "createdAt", "lastSeen") if k in e} for e in exts]

        if head == "pair":
            code = f"{secrets.randbelow(10 ** 6):06d}"
            app.pairing = {"code": code, "expires": time.time() + 300, "tries": 0}
            return {"code": code, "expiresIn": 300}

        raise ApiError("Not found.", 404)

    # ---------- the extension's API ----------
    def ext_api(h, method, route, q, body):
        v = app.vault
        if route == "pair" and method == "POST":
            p = app.pairing
            if not p or p["expires"] < time.time() or p["tries"] >= 5:
                raise ApiError("That code expired. Get a new one in Jace Passwords → Settings → Browser extension.", 403)
            p["tries"] += 1
            if not hmac.compare_digest(str(body.get("code", "")).strip(), p["code"]):
                raise ApiError("That code is wrong.", 403)
            app.pairing = None
            token = secrets.token_urlsafe(32)
            exts = v.device().get("extensions", [])
            exts.append({"id": new_id(), "name": str(body.get("name") or "Browser")[:60], "hash": _hash(token),
                         "createdAt": now_iso(), "lastSeen": now_iso()})
            v.update_device(extensions=exts)
            return {"token": token}

        ext = h._ext_token()
        if not ext:
            raise ApiError("This extension isn't paired with Jace Passwords.", 401)

        if route == "status":
            return {"locked": not v.unlocked, "setup": v.exists(), "account": app.public_account(),
                    "version": APP_VERSION, "keyMode": v.key_mode() if v.exists() else None,
                    "remembered": v.remembered() if v.exists() else False}
        if route == "unlock" and method == "POST":
            app.unlock_vault(body.get("password"))
            return {"ok": True}
        if route == "lock" and method == "POST":
            v.lock()
            return {"ok": True}
        if route == "field-report" and method == "POST":  # "this is the password field", for everyone
            acct = app.jace_account()
            if not acct:
                raise ApiError("Sign in with Jace in the app to share field reports.", 401)
            return jace.report_field(acct["access_token"], str(body.get("host", "")), str(body.get("field", "")),
                                     str(body.get("kind", "")))
        if route == "generate":
            opts = body if method == "POST" else {}
            pw = generator.generate(opts)
            return {"password": pw, "strength": generator.strength(pw)}

        v.require()
        if route == "match":
            url = q.get("url") or body.get("url", "")
            scored = [(security.matches(i, url), i) for i in v.visible_items()]
            logins = [item_summary(i) for s, i in sorted(scored, key=lambda x: (-x[0], x[1].get("title", ""))) if s]
            return {"site": security.site(url), "logins": logins,
                    "cards": [item_summary(i) for i in v.visible_items() if i["type"] == "card"],
                    "identities": [item_summary(i) for i in v.visible_items() if i["type"] == "identity"]}
        if route == "search":
            needle = (q.get("q") or "").lower()
            out = []
            for i in v.visible_items():
                hay = " ".join([i.get("title", ""), i.get("fields", {}).get("username", ""),
                                " ".join(i.get("fields", {}).get("urls") or [])]).lower()
                if needle in hay:
                    out.append(item_summary(i))
            return out[:50]
        if route == "fill" and method == "POST":
            it = v.get_item(body.get("id", ""))
            f = it.get("fields", {})
            v.mark_used(it["id"])
            out = {"type": it["type"], "title": it["title"]}
            if it["type"] == "login":
                out.update(username=f.get("username", ""), password=f.get("password", ""))
                if f.get("totp"):
                    try:
                        out["totp"] = totp.code(f["totp"])["code"]
                    except ValueError:
                        pass
            elif it["type"] == "card":
                out.update({k: f.get(k, "") for k in ("cardholder", "number", "expMonth", "expYear", "cvv", "zip")})
            elif it["type"] == "identity":
                out.update({k: f.get(k, "") for k in ("fullName", "firstName", "lastName", "email", "phone",
                                                       "address1", "address2", "city", "state", "zip", "country",
                                                       "company", "birthday")})
            return out
        if route.startswith("passkey/") and method == "POST":
            kind = route.split("/", 1)[1]
            rp_id, origin = body.get("rpId", ""), body.get("origin", "")
            try:
                if kind == "list":
                    allow = set(body.get("allow") or [])
                    return [{"credentialId": p["credentialId"], "userName": p.get("userName") or i["fields"].get("username", ""),
                             "userDisplayName": p.get("userDisplayName", ""), "title": i["title"], "itemId": i["id"]}
                            for i, p in v.passkeys_for(rp_id) if not allow or p["credentialId"] in allow]
                cdj = passkeys.b64u_dec(body.get("clientDataJSON", ""))
                if kind == "create":
                    existing = {p["credentialId"] for _, p in v.passkeys_for(rp_id)}
                    if existing & set(body.get("exclude") or []):
                        raise passkeys.PasskeyError("You already have a passkey for this account in Jace Passwords.",
                                                    "InvalidStateError")
                    stored, resp = passkeys.register(rp_id, origin, cdj, body.get("user") or {}, body.get("algs") or [])
                    item = v.save_passkey(stored, str(body.get("rpName") or "")[:120])
                    app.after_change()
                    return {**resp, "itemId": item["id"], "title": item["title"]}
                if kind == "get":
                    for i, p in v.passkeys_for(rp_id):
                        if p["credentialId"] == body.get("credentialId"):
                            resp = passkeys.assert_(p, rp_id, origin, cdj)
                            v.touch_passkey(i, p)
                            app.after_change()
                            return resp
                    raise passkeys.PasskeyError("That passkey isn't in your vault.")
            except passkeys.PasskeyError as e:
                raise ApiError(f"{e.name}: {e}", 400)
        if route in ("save-check-item", "save-item") and method == "POST":  # cards and addresses typed into forms
            kind = body.get("type")
            if kind not in ("card", "identity"):
                raise ApiError("Unknown item type.")
            fields = {k: str(val).strip() for k, val in (body.get("fields") or {}).items()
                      if isinstance(val, (str, int)) and str(val).strip() and k != "cvv"}
            title, summary = _item_title(kind, fields)
            match = _find_same(v, kind, fields)
            if route == "save-check-item":
                if not match:
                    return {"status": "new", "title": title, "summary": summary}
                same = all(_norm(match["fields"].get(k)) == _norm(val) for k, val in fields.items())
                return {"status": "unchanged" if same else "update", "title": match["title"], "summary": summary}
            if match:
                v.update_item(match["id"], {"fields": {**match["fields"], **fields}})
                app.after_change()
                return {"status": "updated", "id": match["id"]}
            if kind == "card":
                fields.setdefault("cardType", "credit")
                fields["brand"] = card_brand(fields.get("number", ""))
            it = v.create_item({"type": kind, "title": title, "fields": fields})
            app.after_change()
            return {"status": "created", "id": it["id"]}
        if route == "save-check" and method == "POST":
            url, user, pw = body.get("url", ""), body.get("username", ""), body.get("password", "")
            for i in v.visible_items():
                if security.matches(i, url) and i["fields"].get("username", "") == user:
                    return {"status": "unchanged" if i["fields"].get("password") == pw else "update", "title": i["title"]}
            return {"status": "new", "title": security.site(url)}
        if route == "save" and method == "POST":
            url, user, pw = body.get("url", ""), body.get("username", ""), body.get("password", "")
            if not pw:
                raise ApiError("No password to save.")
            for i in v.visible_items():
                if security.matches(i, url) and i["fields"].get("username", "") == user:
                    if i["fields"].get("password") == pw:
                        return {"status": "unchanged", "id": i["id"]}
                    fields = dict(i["fields"], password=pw)
                    v.update_item(i["id"], {"fields": fields})
                    app.after_change()
                    return {"status": "updated", "id": i["id"]}
            host = security.hostname(url)
            it = v.create_item({"type": "login", "title": body.get("title") or security.site(url) or host,
                                "fields": {"username": user, "password": pw, "urls": [f"https://{host}"] if host else []}})
            app.after_change()
            return {"status": "created", "id": it["id"]}
        raise ApiError("Not found.", 404)

    return Handler


_PAGE = """<!doctype html><meta charset=utf-8><title>Jace Passwords</title>
<style>body{{font-family:system-ui,sans-serif;background:#111317;color:#e6e8eb;display:grid;place-items:center;height:100vh;margin:0}}
div{{max-width:440px;text-align:center}}h1{{color:#3ddc84}}code{{background:#1c1f26;padding:2px 6px;border-radius:6px}}</style>
<div><h1>{title}</h1><p>{text}</p></div>"""
NOT_LAUNCHED = _PAGE.format(title="🔐 Jace Passwords", text="For your safety, this page only opens from the "
                            "Jace Passwords app. Open it from your apps menu, or run <code>./run.sh</code>.")
SIGNED_IN = _PAGE


def start(app: App):
    """Starts the server on a background thread. Returns (server, launch URL), or None if the
    port is taken (usually: Jace Passwords is already running)."""
    try:
        httpd = ThreadingHTTPServer((HOST, PORT), make_handler(app))
    except OSError:
        return None
    httpd.daemon_threads = True
    from . import data_dir
    write_private(data_dir() / "server.json", json.dumps({"port": PORT, "launch": app.launch_key}))
    threading.Thread(target=app.autolock_loop, daemon=True).start()
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    app.auto_sign_in()
    return httpd, f"http://{HOST}:{PORT}/?launch={app.launch_key}"


def show_running_copy() -> bool:
    """Asks an already-running Jace Passwords to show its window. True if one answered."""
    import urllib.request
    from . import data_dir
    try:
        info = json.loads((data_dir() / "server.json").read_text())
        req = urllib.request.Request(f"http://{HOST}:{info['port']}/app/show",
                                     data=json.dumps({"key": info["launch"]}).encode(), method="POST")
        with urllib.request.urlopen(req, timeout=3) as r:
            return r.status == 200
    except Exception:  # noqa: BLE001
        return False


def serve(app: App, open_browser=True):
    """Browser mode (python3 -m jace_passwords --browser): serve until Ctrl+C."""
    started = start(app)
    if not started:
        return False
    httpd, url = started
    print(f"{APP_NAME} {APP_VERSION} is running at http://{HOST}:{PORT}", flush=True)
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    else:
        print(f"Open: {url}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return True
