"""Watchtower: weak, reused, old and breached passwords, missing 2FA, expiring cards — plus URL matching for autofill."""
import hashlib
import urllib.parse
import urllib.request
from datetime import datetime, timezone

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


def report(items: list) -> dict:
    logins = [i for i in items if i.get("type") == "login" and not i.get("deletedAt")]
    by_pw: dict[str, list] = {}
    for i in logins:
        pw = i.get("fields", {}).get("password")
        if pw:
            by_pw.setdefault(pw, []).append(i["id"])

    weak, reused, old, no2fa, insecure, expiring = [], [], [], [], [], []
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
        if not f.get("totp") and not f.get("signInWith") and not f.get("passkeys") and any(site(u) in TWO_FA_SITES for u in urls):
            no2fa.append(i["id"])
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

    issues = len(set(weak + reused + old + no2fa + insecure))
    score = 100 if not logins else max(0, round(100 - 100 * issues / len(logins) * 0.8 - len(expiring) * 2))
    return {"score": score, "total": len(logins), "weak": weak, "reused": reused, "old": old,
            "missing2fa": no2fa, "insecure": insecure, "expiring": expiring}


def pwned_count(password: str) -> int:
    """Have I Been Pwned, k-anonymity: only the first 5 hex chars of the SHA-1 leave this computer."""
    h = hashlib.sha1(password.encode()).hexdigest().upper()
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{h[:5]}",
                                 headers={"User-Agent": "JacePasswords/1.0", "Add-Padding": "true"})
    with urllib.request.urlopen(req, timeout=15) as r:
        for line in r.read().decode().splitlines():
            suffix, _, count = line.partition(":")
            if suffix == h[5:]:
                return int(count)
    return 0
