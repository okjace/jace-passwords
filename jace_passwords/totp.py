"""Two-factor codes (TOTP, RFC 6238) stored right on a login, including Steam Guard's 5-character codes."""
import base64
import json
import hashlib
import hmac
import struct
import time
import urllib.parse

ALGOS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256, "SHA512": hashlib.sha512}
STEAM_CHARS = "23456789BCDFGHJKMNPQRTVWXY"  # Steam Guard codes: 5 of these, from the same HMAC as TOTP


def _steam(secret: str) -> dict:
    return {"secret": secret, "digits": 5, "period": 30, "algorithm": "SHA1", "issuer": "Steam", "account": "", "steam": True}


def parse(value: str) -> dict:
    """Accepts an otpauth:// URI or a bare base32 secret. Raises ValueError if neither."""
    value = (value or "").strip()
    if value.startswith("{"):  # a Steam Desktop Authenticator .maFile: its base64 "shared_secret"
        try:
            shared = json.loads(value)["shared_secret"]
            value = "steam://" + base64.b32encode(base64.b64decode(shared)).decode().rstrip("=")
        except (ValueError, KeyError, TypeError) as e:
            raise ValueError("That isn't a Steam Guard file (it needs a shared_secret).") from e
    if value.lower().startswith("steam://"):  # Bitwarden / KeePassXC style
        cfg = _steam(_clean(value[8:]))
        _decode(cfg["secret"])
        return cfg
    if value.lower().startswith("otpauth://"):
        u = urllib.parse.urlparse(value)
        q = {k.lower(): v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if u.netloc.lower() == "steam" or q.get("encoder", "").lower() == "steam":  # Aegis, KeePass
            cfg = _steam(_clean(q.get("secret", "")))
            cfg["account"] = urllib.parse.unquote(u.path.lstrip("/")).split(":", 1)[-1]
            _decode(cfg["secret"])
            return cfg
        if u.netloc.lower() != "totp":
            raise ValueError("Only time-based (TOTP) and Steam Guard codes are supported.")
        label = urllib.parse.unquote(u.path.lstrip("/"))
        issuer = q.get("issuer") or (label.split(":", 1)[0] if ":" in label else "")
        cfg = {
            "secret": _clean(q.get("secret", "")),
            "digits": int(q.get("digits", 6)),
            "period": int(q.get("period", 30)),
            "algorithm": q.get("algorithm", "SHA1").upper(),
            "issuer": issuer,
            "account": label.split(":", 1)[-1] if label else "",
        }
    else:
        cfg = {"secret": _clean(value), "digits": 6, "period": 30, "algorithm": "SHA1", "issuer": "", "account": ""}
    if cfg["algorithm"] not in ALGOS or cfg["digits"] not in (6, 7, 8) or not 10 <= cfg["period"] <= 120:
        raise ValueError("Unsupported two-factor settings.")
    _decode(cfg["secret"])
    return cfg


def _clean(s: str) -> str:
    return "".join(s.split()).replace("-", "").upper()


def _decode(secret: str) -> bytes:
    if not secret:
        raise ValueError("That two-factor secret is empty.")
    try:
        return base64.b32decode(secret + "=" * (-len(secret) % 8))
    except Exception as e:
        raise ValueError("That isn't a valid two-factor secret (it should be base32 letters A–Z and 2–7).") from e


def code(value: str, at: float | None = None) -> dict:
    cfg = parse(value)
    now = time.time() if at is None else at
    counter = int(now // cfg["period"])
    mac = hmac.new(_decode(cfg["secret"]), struct.pack(">Q", counter), ALGOS[cfg["algorithm"]]).digest()
    off = mac[-1] & 0x0F
    full = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    if cfg.get("steam"):
        chars = []
        for _ in range(5):
            chars.append(STEAM_CHARS[full % len(STEAM_CHARS)])
            full //= len(STEAM_CHARS)
        text = "".join(chars)
    else:
        text = str(full % (10 ** cfg["digits"])).zfill(cfg["digits"])
    return {
        "code": text,
        "steam": bool(cfg.get("steam")),
        "period": cfg["period"],
        "remaining": cfg["period"] - int(now % cfg["period"]),
        "issuer": cfg["issuer"],
    }
