"""Self-update from GitHub releases, so the desktop app updates without you downloading anything.

1. check():    the latest release, and the file for this computer (AppImage / setup .exe / .app.zip)
2. download(): fetched into the data folder in the background, checked against GitHub's SHA-256
3. apply():    the new copy is started with --apply-update --wait-pid <this app>; this app quits;
               the new copy waits for it to close, installs itself over the installed one (same folder,
               same shortcuts: it's the installer's own install step) and starts it again.
Only installed, packaged copies update this way (not one run from source).
"""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .. import APP_VERSION, GITHUB_REPO, data_dir, net
from . import install


def _newer(a: str, b: str) -> bool:
    def parts(v):
        return tuple(int(x) if x.isdigit() else 0 for x in v.lstrip("v").split("."))
    return parts(a) > parts(b)


def asset_name(version: str) -> str | None:
    if install.IS_WIN:
        return f"JacePasswords-{version}-windows-x64.exe"
    if install.IS_MAC:
        arch = "arm64" if platform.machine() == "arm64" else "x86_64"
        return f"JacePasswords-{version}-macos-{arch}.app.zip"
    if sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64"):
        return f"JacePasswords-{version}-x86_64.AppImage"
    return None


def can_self_update() -> bool:
    return install.frozen() and install.running_installed_copy() and asset_name(APP_VERSION) is not None


def check() -> dict | None:
    """{"version", "url", "size", "sha256", "page"} if a newer release has a file for this computer."""
    req = urllib.request.Request(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                                 headers={"User-Agent": f"JacePasswords/{APP_VERSION}", "Accept": "application/vnd.github+json"})
    with net.urlopen(req, timeout=20) as r:
        rel = json.loads(r.read())
    version = rel.get("tag_name", "").lstrip("v")
    if not version or not _newer(version, APP_VERSION):
        return None
    want = asset_name(version)
    for a in rel.get("assets", []):
        if a.get("name") == want:
            digest = a.get("digest") or ""
            return {"version": version, "url": a["browser_download_url"], "size": a.get("size") or 0,
                    "sha256": digest.split(":", 1)[1] if digest.startswith("sha256:") else "", "page": rel.get("html_url")}
    return {"version": version, "url": "", "page": rel.get("html_url")}  # newer, but no file for this computer


def updates_dir() -> Path:
    d = data_dir() / "updates"
    d.mkdir(parents=True, exist_ok=True)
    return d


def download(info: dict, progress=None) -> Path:
    """Downloads (or reuses) the new version; returns the runnable package (AppImage, .exe or .app)."""
    name = info["url"].rsplit("/", 1)[-1]
    target = updates_dir() / name
    if not target.exists():
        part = target.with_suffix(target.suffix + ".partial")
        req = urllib.request.Request(info["url"], headers={"User-Agent": f"JacePasswords/{APP_VERSION}"})
        h = hashlib.sha256()
        got = 0
        with net.urlopen(req, timeout=60) as r, open(part, "wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
                h.update(chunk)
                got += len(chunk)
                if progress and info.get("size"):
                    progress(got / info["size"])
        if info.get("sha256") and h.hexdigest() != info["sha256"]:
            part.unlink(missing_ok=True)
            raise RuntimeError("The download didn't match GitHub's checksum. Try again later.")
        if info.get("size") and got != info["size"]:
            part.unlink(missing_ok=True)
            raise RuntimeError("The download was incomplete. Try again later.")
        part.replace(target)
    if install.IS_MAC:
        out = updates_dir() / f"mac-{info['version']}"
        app = out / f"{install.APP_NAME}.app"
        if not app.exists():
            shutil.rmtree(out, ignore_errors=True)
            out.mkdir(parents=True)
            subprocess.run(["ditto", "-x", "-k", str(target), str(out)], check=True)
        return app
    target.chmod(0o755)
    return target


def apply(package: Path) -> None:
    """Starts the new version's installer step; the caller then quits so it can replace this copy."""
    args = ["--apply-update", "--wait-pid", str(os.getpid())]
    env = {k: v for k, v in os.environ.items() if k not in ("APPIMAGE", "APPDIR", "ARGV0", "OWD", "_MEIPASS2")}
    env.pop("LD_LIBRARY_PATH", None)
    if install.IS_MAC:
        subprocess.Popen([str(package / "Contents" / "MacOS" / install.APP_NAME), *args], start_new_session=True, env=env)
    elif install.IS_WIN:
        subprocess.Popen([str(package), *args], env=env, close_fds=True,
                         creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP)
    else:
        subprocess.Popen([str(package), *args], env=env, start_new_session=True, close_fds=True)


def _wait_for_pid(pid: int, timeout=120):
    deadline = time.time() + timeout
    if install.IS_WIN:
        import ctypes
        h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE
        if h:
            ctypes.windll.kernel32.WaitForSingleObject(h, int(timeout * 1000))
            ctypes.windll.kernel32.CloseHandle(h)
        time.sleep(1)  # let Windows release the files
        return
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except OSError:
            return
        try:  # Linux: a process that has exited but not been reaped yet ("zombie") counts as closed
            if Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].startswith("Z"):
                return
        except (OSError, IndexError):
            pass
        time.sleep(0.3)


def apply_cli(argv) -> int:
    """Runs in the NEW version: wait for the old app to quit, install over it, start it."""
    pid = int(argv[argv.index("--wait-pid") + 1]) if "--wait-pid" in argv else 0
    if pid:
        _wait_for_pid(pid)
    rec = install.install_record()
    installed = install.installed_path()
    if not installed:
        return 1
    target = installed.parent
    opts = {p: True for p in rec.get("parts", [])}
    log = data_dir() / "update.log"
    try:
        path = install.install(target, opts, status=lambda s: None)
        log.write_text(f"Updated to {APP_VERSION} at {time.ctime()}\n")
    except Exception as e:  # noqa: BLE001 - leave the old copy running
        log.write_text(f"Update to {APP_VERSION} failed: {e}\n")
        install.relaunch(installed)
        return 1
    if "--no-relaunch" not in argv:
        install.relaunch(path, *(["--background"] if "--background" in argv else []))
    return 0


def cleanup():
    """Removes downloaded updates that are already installed (not the running one)."""
    d = data_dir() / "updates"
    if not d.exists():
        return
    running = install.running_package()
    for p in d.iterdir():
        if running and (p == running or p in running.parents):
            continue
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            p.unlink(missing_ok=True)
