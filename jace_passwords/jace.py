"""Sign in with Jace (OAuth 2.0 + PKCE) and end-to-end encrypted vault sync.

The redirect lands on this app's own local server (/jace/callback). Sync stores
the vault file — already sealed with your master password + Secret Key — in
Jace's "pw-vault" sync collection, so Jace only ever holds ciphertext.
"""
import base64
import hashlib
import json
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from . import APP_VERSION, CLIENT_ID, HOST, JACE_URL, PORT, SYNC_COLLECTION, net

UA = f"JacePasswords/{APP_VERSION}"
NOT_DEPLOYED = ("Jace doesn't support Jace Passwords sync yet: deploy Jace with the \"pw-vault\" collection "
                "(lib/browserSync.ts). Your vault is safe on this computer.")
REDIRECT = f"http://{HOST}:{PORT}/jace/callback"


class JaceError(Exception):
    pass


class Conflict(JaceError):
    pass


def _request(method: str, url: str, form=None, body=None, token=None, headers=None):
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
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with net.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read().decode())
        except ValueError:
            err = {"error": str(e)}
        return e.code, err
    except urllib.error.URLError as e:
        import ssl
        if isinstance(e.reason, ssl.SSLError):
            raise JaceError(f"Couldn't check Jace's security certificate ({e.reason.reason or e.reason}).") from e
        raise JaceError("Couldn't reach Jace. Check your internet connection.") from e
    except (TimeoutError, socket.timeout) as e:
        raise JaceError("Jace took too long to answer. Try again.") from e


class Auth:
    """One pending browser sign-in at a time."""

    def __init__(self):
        self.pending: dict | None = None

    def start(self) -> str:
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        state = secrets.token_urlsafe(24)
        self.pending = {"state": state, "verifier": verifier, "at": time.time()}
        return f"{JACE_URL}/oauth/authorize?" + urllib.parse.urlencode({
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT,
            "scope": "profile sync",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        })

    def finish(self, query: dict) -> dict:
        p, self.pending = self.pending, None
        if not p or time.time() - p["at"] > 600 or query.get("state") != p["state"]:
            raise JaceError("That sign-in didn't match. Please try again.")
        if query.get("error"):
            raise JaceError(query.get("error_description") or query["error"])
        status, tok = _request("POST", f"{JACE_URL}/api/oauth/token", form={
            "grant_type": "authorization_code", "code": query.get("code", ""), "redirect_uri": REDIRECT,
            "client_id": CLIENT_ID, "code_verifier": p["verifier"]})
        if status != 200 or not tok.get("access_token"):
            raise JaceError(tok.get("error_description") or tok.get("error") or "Jace didn't send a sign-in token.")
        status, user = _request("GET", f"{JACE_URL}/api/oauth/userinfo", token=tok["access_token"])
        if status != 200:
            raise JaceError("Couldn't read your Jace profile.")
        return {
            "access_token": tok["access_token"],
            "expires_at": time.time() + float(tok.get("expires_in") or 0) if tok.get("expires_in") else 0,
            "scope": tok.get("scope", ""),
            "user": user,
        }


def account_from_token(access_token: str, expires_in=None, scope: str = "") -> dict:
    """A signed-in account record (what Auth.finish saves) for an access token, e.g. one from Jace OS."""
    status, user = _request("GET", f"{JACE_URL}/api/oauth/userinfo", token=access_token)
    if status != 200:
        raise JaceError("Couldn't read your Jace profile.")
    return {"access_token": access_token,
            "expires_at": time.time() + float(expires_in) if expires_in else 0,
            "scope": scope, "user": user}


def public_user(u: dict) -> dict:
    return {"id": str(u.get("sub") or u.get("id") or ""), "username": u.get("preferred_username") or u.get("username") or "",
            "name": u.get("display_name") or u.get("name") or "", "picture": u.get("picture") or ""}


def pull(token: str) -> tuple[dict | None, int]:
    """(vault file, version) from Jace, or (None, 0) if nothing's synced yet."""
    status, r = _request("GET", f"{JACE_URL}/api/oauth/sync/{SYNC_COLLECTION}", token=token)
    if status == 404:
        if "Unknown sync collection" in str(r.get("error_description", "")):
            raise JaceError(NOT_DEPLOYED)
        return None, 0
    if status == 401:
        raise JaceError("Your Jace sign-in expired. Sign in again.")
    if status != 200:
        raise JaceError(r.get("error_description") or f"Jace sync failed ({status}).")
    try:
        return json.loads(base64.b64decode(r["payload"])), int(r["version"])
    except (KeyError, ValueError) as e:
        raise JaceError("The vault on Jace is damaged.") from e


def push(token: str, vault_file: dict, version: int, device: str) -> int:
    payload = base64.b64encode(json.dumps(vault_file, separators=(",", ":")).encode()).decode()
    status, r = _request("PUT", f"{JACE_URL}/api/oauth/sync/{SYNC_COLLECTION}", token=token,
                         body={"payload": payload, "device": device}, headers={"If-Match": f'"{version}"'})
    if status == 412:
        raise Conflict("changed elsewhere")
    if status == 404:
        raise JaceError(NOT_DEPLOYED)
    if status != 200:
        raise JaceError(r.get("error_description") or f"Jace sync failed ({status}).")
    return int(r["version"])


def delete_remote(token: str) -> None:
    _request("DELETE", f"{JACE_URL}/api/oauth/sync/{SYNC_COLLECTION}", token=token)
