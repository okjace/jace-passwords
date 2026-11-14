"""Jace Passwords — an end-to-end encrypted password manager tied to your Jace account."""
import os
import sys
from pathlib import Path

APP_NAME = "Jace Passwords"
APP_VERSION = "1.6.5"
APP_RELEASE_DATE = "2026-11-13"
AUTHOR = "jace.deb"
GITHUB_REPO = "okjace/jace-passwords"
GITHUB_URL = f"https://github.com/{GITHUB_REPO}"
APP_ID = "io.github.okjace.JacePasswords"

# Jace (okjace/Jace). Sign in with Jace uses OAuth 2.0 + PKCE on a loopback redirect,
# so there's no client secret. The client row is seeded by Jace's lib/schema.sql.
JACE_URL = os.environ.get("JACE_URL", "https://jaceo.vercel.app").rstrip("/")
CLIENT_ID = os.environ.get("JACE_PASSWORDS_CLIENT_ID", "00000000-0000-0000-0000-000000000004")
SYNC_COLLECTION = "pw-vault"
# The Jace Passwords web app. Also hands out the key for vaults unlocked with Jace (no master password).
WEB_URL = os.environ.get("JACE_PASSWORDS_WEB_URL", "https://jace-passwords.vercel.app").rstrip("/")

HOST = "127.0.0.1"
PORT = int(os.environ.get("JACE_PASSWORDS_PORT", "47620"))


def data_dir() -> Path:
    base = os.environ.get("JACE_PASSWORDS_HOME")
    if base:
        d = Path(base)
    elif sys.platform == "win32":
        d = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming") / "Jace Passwords"
    elif sys.platform == "darwin":
        d = Path.home() / "Library" / "Application Support" / "Jace Passwords"
    else:
        d = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "jace-passwords"
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass
    return d


def write_private(path: Path, text: str) -> None:
    """Atomically writes a file only you can read."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    tmp.replace(path)
