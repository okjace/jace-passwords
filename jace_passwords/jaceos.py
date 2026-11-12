"""Signing in with the computer's Jace account on Jace OS (like Jace Social).

Jace OS ships `jace-account`: `--json` says whether the computer is signed in to Jace, and
`--token-for <client_id>` trades the computer's Jace token for one issued to another official Jace
app (Jace's RFC 8693 token exchange). So on Jace OS, Jace Passwords signs in without asking.
"""
import json
import os
import shutil
import subprocess
import sys

TOOL = "jace-account"


def available() -> bool:
    return sys.platform.startswith("linux") and shutil.which(TOOL) is not None


def _host_env() -> dict:
    """The computer's own environment, without what PyInstaller / the AppImage add (their libraries
    would break the system's Python that jace-account runs on)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith(("_PYI", "_MEI"))}
    for name in ("LD_LIBRARY_PATH", "LD_PRELOAD"):
        orig = env.pop(f"{name}_ORIG", None)
        if orig is not None:
            env[name] = orig
        elif getattr(sys, "frozen", False):
            env.pop(name, None)
    for name in ("PYTHONHOME", "PYTHONPATH", "QT_PLUGIN_PATH", "QML2_IMPORT_PATH", "APPIMAGE", "APPDIR"):
        env.pop(name, None)
    return env


def _tool(*args: str, timeout: float) -> dict:
    try:
        r = subprocess.run([TOOL, *args], capture_output=True, text=True, timeout=timeout, env=_host_env())
        out = json.loads(r.stdout or "{}")
        return out if isinstance(out, dict) and r.returncode == 0 else {}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


def signed_in() -> bool:
    return available() and bool(_tool("--json", timeout=10).get("signed_in"))


def token_for(client_id: str, scope: str) -> dict:
    """{"access_token", "expires_in", "scope"} for this app, or {} if Jace OS can't give one."""
    if not signed_in():
        return {}
    got = _tool("--token-for", client_id, "--scope", scope, timeout=30)
    return got if isinstance(got.get("access_token"), str) and got["access_token"] else {}
