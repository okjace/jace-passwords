"""Import from other password managers' CSV exports; export to CSV."""
import csv
import io

# lower-case header -> our field
COLUMNS = {
    "title": ["title", "name", "account", "item name"],
    "url": ["url", "login_uri", "website", "web site", "login url", "urls", "origin"],
    "username": ["username", "login_username", "user name", "login", "email", "login name"],
    "password": ["password", "login_password"],
    "totp": ["totp", "otpauth", "login_totp", "one-time password", "otp", "2fa"],
    "notes": ["notes", "note", "extra", "comments"],
    "type": ["type"],
    "vault": ["vault", "folder", "grouping"],
}


def _get(row: dict, key: str) -> str:
    for name in COLUMNS[key]:
        if name in row and row[name]:
            return row[name].strip()
    return ""


def parse_csv(text: str) -> list[dict]:
    """Chrome, Firefox, Edge, Safari, Bitwarden, 1Password, Proton Pass, LastPass, Dashlane-ish CSVs."""
    text = text.lstrip("﻿")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    out = []
    for raw in reader:
        row = {(k or "").strip().lower(): (v or "") for k, v in raw.items()}
        kind = _get(row, "type").lower()
        notes = _get(row, "notes")
        url, user, pw = _get(row, "url"), _get(row, "username"), _get(row, "password")
        title = _get(row, "title")
        if kind in ("note", "securenote", "secure note") or (not (url or user or pw) and notes):
            out.append({"type": "note", "title": title or "Imported note", "fields": {"body": notes}})
            continue
        if not (url or user or pw):
            continue
        urls = [u.strip() for u in url.replace(",", "\n").splitlines() if u.strip()]
        if not title:
            from .security import hostname
            title = hostname(urls[0]) if urls else user or "Imported login"
        out.append({"type": "login", "title": title, "folder": _get(row, "vault"),
                    "fields": {"username": user, "password": pw, "urls": urls, "totp": _get(row, "totp"), "notes": notes}})
    return out


def to_csv(items: list) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["type", "title", "url", "username", "password", "totp", "notes"])
    for i in items:
        f = i.get("fields", {})
        if i.get("type") == "login":
            w.writerow(["login", i["title"], ",".join(f.get("urls") or []), f.get("username", ""),
                        f.get("password", ""), f.get("totp", ""), f.get("notes", "")])
        elif i.get("type") == "note":
            w.writerow(["note", i["title"], "", "", "", "", f.get("body", "")])
    return buf.getvalue()
