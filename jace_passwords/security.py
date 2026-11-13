"""Watchtower: weak, reused, old and breached passwords, missing 2FA, expiring cards — plus URL matching for autofill."""
import hashlib
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from . import net
from .generator import strength

MULTI_PART_TLDS = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
                   "com.br", "com.mx", "co.in", "co.za", "com.tr", "com.cn", "com.sg", "com.hk", "vercel.app",
                   "github.io", "netlify.app", "pages.dev", "herokuapp.com"}

# Sites that offer two-factor codes, so Watchtower can suggest turning it on.
TWO_FA_SITES = {"google.com", "github.com", "microsoft.com", "live.com", "apple.com", "icloud.com", "amazon.com",
                "facebook.com", "instagram.com", "x.com", "twitter.com", "discord.com", "reddit.com", "paypal.com",
                "dropbox.com", "slack.com", "twitch.tv", "steampowered.com", "epicgames.com", "linkedin.com",
                "coinbase.com", "binance.com", "proton.me", "1password.com", "bitwarden.com", "gitlab.com",
                "npmjs.com", "cloudflare.com", "digitalocean.com", "aws.amazon.com", "vercel.com", "netlify.com",
                "stripe.com", "shopify.com", "zoom.us", "tiktok.com", "snapchat.com", "yahoo.com", "ebay.com",
                "roblox.com", "minecraft.net", "nintendo.com", "playstation.com", "xbox.com", "jaceo.vercel.app"}


def hostname(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if "://" not in url:
        url = "https://" + url
    try:
        return (urllib.parse.urlparse(url).hostname or "").lower().removeprefix("www.")
    except ValueError:
        return ""


def site(url: str) -> str:
    """The registrable domain (accounts.google.com -> google.com), close enough for matching."""
    h = hostname(url)
    if not h or h.replace(".", "").isdigit() or h == "localhost":
        return h
    parts = h.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def matches(item: dict, url: str) -> int:
    """0 = no match, 1 = same site, 2 = same host. Logins only."""
    if item.get("type") != "login" or item.get("deletedAt"):
        return 0
    h, s = hostname(url), site(url)
    best = 0
    for u in item.get("fields", {}).get("urls", []) or []:
        uh = hostname(u)
        if uh and uh == h:
            return 2
        if s and site(u) == s:
            best = 1
    return best


def _age_days(iso: str | None) -> float:
    if not iso:
        return 0
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - t).total_seconds() / 86400
    except ValueError:
        return 0


# ---------- established public data (fetched by the app, cached for a day; same for everyone) ----------
SOURCES = {
    "tfa": "https://api.2fa.directory/v3/tfa.json",                  # 2fa.directory: sites that support 2FA
    "passkeys": "https://passkeys-api.2fa.directory/v1/supported.json",  # passkeys.directory: sites with passkeys
    "breaches": "https://haveibeenpwned.com/api/v3/breaches",        # Have I Been Pwned: breached websites
}


def compact_tfa(raw) -> dict:
    """domain -> {"methods": [...], "doc": url} from 2fa.directory's list."""
    out = {}
    for _name, e in raw or []:
        info = {"methods": e.get("tfa") or [], "doc": e.get("documentation") or ""}
        for d in [e.get("domain")] + (e.get("additional-domains") or []):
            if d:
                out[d.lower()] = info
    return out


def compact_passkeys(raw) -> dict:
    """domain -> {"passwordless": bool, "mfa": bool, "doc": url} from the passkeys directory."""
    return {d.lower(): {"passwordless": bool(v.get("passwordless")), "mfa": bool(v.get("mfa")), "doc": v.get("documentation") or ""}
            for d, v in (raw or {}).items()}


def compact_breaches(raw) -> dict:
    """domain -> [{name, date, added, count, passwords}] from Have I Been Pwned (real breaches only)."""
    out: dict = {}
    for b in raw or []:
        d = (b.get("Domain") or "").lower()
        if not d or b.get("IsSpamList") or b.get("IsFabricated") or b.get("IsRetired"):
            continue
        out.setdefault(d, []).append({"name": b.get("Title") or b.get("Name"), "date": b.get("BreachDate") or "",
                                      "added": b.get("AddedDate") or "", "count": b.get("PwnCount") or 0,
                                      "passwords": "Passwords" in (b.get("DataClasses") or [])})
    return out


def watchtower_data(cache_dir=None, max_age=86400) -> dict:
    """The three lists, from the cache if it's under a day old. Missing ones come back empty."""
    import json
    import time
    from . import data_dir, net
    path = (cache_dir or data_dir()) / "watchtower-cache.json"
    try:
        cached = json.loads(path.read_text())
    except (OSError, ValueError):
        cached = {}
    if cached.get("at", 0) > time.time() - max_age and all(k in cached for k in SOURCES):
        return cached
    fresh = {"at": time.time()}
    for key, url in SOURCES.items():
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "JacePasswords (password manager Watchtower)",
                                                       "Accept": "application/json"})
            with net.urlopen(req, timeout=30) as r:
                raw = json.loads(r.read())
            fresh[key] = {"tfa": compact_tfa, "passkeys": compact_passkeys, "breaches": compact_breaches}[key](raw)
        except Exception:  # noqa: BLE001 - offline: keep yesterday's list if there is one
            if key in cached:
                fresh[key] = cached[key]
    try:
        path.write_text(json.dumps(fresh))
    except OSError:
        pass
    return fresh


def _lookup(table: dict, url: str):
    """The entry for a URL's host, or its registrable site (accounts.google.com -> google.com)."""
    if not table:
        return None
    h, s = hostname(url), site(url)
    return table.get(h) or table.get(s)


def report(items: list, data: dict | None = None) -> dict:
    logins = [i for i in items if i.get("type") == "login" and not i.get("deletedAt")]
    by_pw: dict[str, list] = {}
    for i in logins:
        pw = i.get("fields", {}).get("password")
        if pw:
            by_pw.setdefault(pw, []).append(i["id"])

    data = data or {}
    tfa, pk_sites, breaches = data.get("tfa") or {}, data.get("passkeys") or {}, data.get("breaches") or {}
    weak, reused, old, no2fa, insecure, expiring = [], [], [], [], [], []
    passkeys_available, compromised, details = [], [], {}
    for i in logins:
        f = i.get("fields", {})
        pw = f.get("password") or ""
        if pw and strength(pw)["score"] <= 1:
            weak.append(i["id"])
        if pw and len(by_pw.get(pw, [])) > 1:
            reused.append(i["id"])
        if pw and _age_days(i.get("passwordChangedAt") or i.get("createdAt")) > 365:
            old.append(i["id"])
        urls = f.get("urls") or []
        info = {}
        t = next((x for x in (_lookup(tfa, u) for u in urls) if x), None)
        if t:
            info["tfa"] = t
        if not f.get("totp") and not f.get("signInWith") and not f.get("passkeys"):
            if (t and t["methods"]) or (not tfa and any(site(u) in TWO_FA_SITES for u in urls)):
                no2fa.append(i["id"])
        pkinfo = next((x for x in (_lookup(pk_sites, u) for u in urls) if x), None)
        if pkinfo:
            info["passkeys"] = pkinfo
            if not f.get("passkeys") and not f.get("signInWith"):
                passkeys_available.append(i["id"])
        changed = (i.get("passwordChangedAt") or i.get("createdAt") or "")[:10]
        hits = [b for u in urls for b in (_lookup(breaches, u) or [])]
        newer = [b for b in hits if b["passwords"] and pw and (not changed or (b["added"][:10] or b["date"]) >= changed)]
        if newer:
            compromised.append(i["id"])
            info["breach"] = max(newer, key=lambda b: b["added"] or b["date"])
        elif hits:
            info["pastBreach"] = max(hits, key=lambda b: b["added"] or b["date"])
        if info:
            details[i["id"]] = info
        if any(u.strip().lower().startswith("http://") and hostname(u) not in ("localhost", "127.0.0.1") for u in urls):
            insecure.append(i["id"])

    today = datetime.now()
    for c in items:
        if c.get("type") != "card" or c.get("deletedAt"):
            continue
        f = c.get("fields", {})
        try:
            m, y = int(f.get("expMonth") or 0), int(f.get("expYear") or 0)
        except ValueError:
            continue
        if not (m and y):
            continue
        if y < 100:
            y += 2000
        months_left = (y - today.year) * 12 + (m - today.month)
        if months_left <= 2:
            expiring.append(c["id"])

    # Vulnerabilities count fully; recommendations (old password, 2FA you could turn on) a quarter.
    vulnerable = set(weak + reused + compromised + insecure)
    advice = set(old + no2fa) - vulnerable
    penalty = (len(vulnerable) + 0.25 * len(advice)) / len(logins) if logins else 0
    score = 100 if not logins else max(0, round(100 - 100 * penalty * 0.8 - len(expiring) * 2))
    return {"score": score, "total": len(logins), "weak": weak, "reused": reused, "old": old,
            "missing2fa": no2fa, "insecure": insecure, "expiring": expiring,
            "compromised": compromised, "passkeysAvailable": passkeys_available, "details": details,
            "sources": {k: bool(data.get(k)) for k in SOURCES}}


def pwned_count(password: str) -> int:
    """Have I Been Pwned, k-anonymity: only the first 5 hex chars of the SHA-1 leave this computer."""
    h = hashlib.sha1(password.encode()).hexdigest().upper()
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{h[:5]}",
                                 headers={"User-Agent": "JacePasswords/1.0", "Add-Padding": "true"})
    with net.urlopen(req, timeout=15) as r:
        for line in r.read().decode().splitlines():
            suffix, _, count = line.partition(":")
            if suffix == h[5:]:
                return int(count)
    return 0
