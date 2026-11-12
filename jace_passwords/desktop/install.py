"""Self-installer, like Jace Launcher's: the downloaded file installs itself.

  Linux    JacePasswords-<ver>-x86_64.AppImage   copied to ~/Applications, plus an applications-menu
                                                 entry, desktop shortcut, terminal command, AppStream info
  Windows  JacePasswords-<ver>-windows-x64.exe   a onefile build that unpacks into
                                                 %LOCALAPPDATA%\\Programs\\Jace Passwords (fast onedir copy),
                                                 Start menu + desktop shortcuts, "Installed apps" entry
  macOS    JacePasswords-<ver>-macos-<arch>.app.zip   Jace Passwords.app copied to Applications, Dock,
                                                 Desktop alias, "downloaded from the internet" flag removed

Every platform can also start Jace Passwords in the tray when you sign in to the computer, so the
browser extension can autofill without opening the window first.

Your vault is never touched by install, update or uninstall (only --uninstall --purge deletes it).
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from .. import APP_ID, APP_NAME, APP_VERSION, AUTHOR, GITHUB_URL, data_dir, write_private

IS_WIN, IS_MAC = sys.platform == "win32", sys.platform == "darwin"
HOME = Path.home()
ICON_PNG = Path(__file__).resolve().parent / "icon.png"

# ---- shared ---------------------------------------------------------------------------------


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def record_path() -> Path:
    return data_dir() / "install.json"


def install_record() -> dict:
    try:
        return json.loads(record_path().read_text())
    except (OSError, ValueError):
        return {}


def installed_path() -> Path | None:
    p = install_record().get("path")
    return Path(p) if p and Path(p).exists() else None


def running_package() -> Path | None:
    """What we're running from: the AppImage, the .app, or the .exe (None when run from source)."""
    if not frozen():
        return None
    if os.environ.get("APPIMAGE") and Path(os.environ["APPIMAGE"]).is_file():
        return Path(os.environ["APPIMAGE"])
    if IS_MAC:
        app = Path(sys.executable).resolve().parents[2]
        return app if app.suffix == ".app" else None
    if IS_WIN:
        return Path(sys.executable)
    return None


def is_setup_build() -> bool:
    """Windows: True for the downloaded onefile .exe (it carries the small installed launcher)."""
    return IS_WIN and frozen() and (Path(getattr(sys, "_MEIPASS", "")) / "jp_setup" / EXE_NAME).is_file()


def running_installed_copy() -> bool:
    src, dst = running_package(), installed_path()
    if IS_WIN and src and dst:
        return src.resolve() == dst.resolve() and not is_setup_build()
    return bool(src and dst and src.resolve() == dst.resolve())


def setup_available() -> bool:
    return running_package() is not None


def launch_command(path: Path, *args: str) -> list[str]:
    if IS_MAC:
        return [str(path / "Contents" / "MacOS" / APP_NAME), *args]
    return [str(path), *args]


# ---- options shown in the wizard ------------------------------------------------------------

def options() -> list[tuple[str, str, bool]]:
    common = [("autostart", "Start Jace Passwords in the background when I sign in (so autofill always works)", True)]
    if IS_WIN:
        return [("startmenu", "Add to the Start menu", True),
                ("desktop", "Create a desktop shortcut", True),
                ("apps", "Show in Windows \"Installed apps\" (so you can uninstall it from Settings)", True),
                *common]
    if IS_MAC:
        return [("dock", "Keep in the Dock", True),
                ("desktop", "Create a desktop shortcut", True),
                ("unquarantine", "Remove the \"downloaded from the internet\" flag (stops the \"damaged\" warning)", True),
                *common]
    return [("menu", "Add to the applications menu", True),
            ("desktop", "Create a desktop shortcut", True),
            ("terminal", "Add the  jace-passwords  terminal command", True),
            ("appstream", "Show in GNOME Software, KDE Discover and other app centers", True),
            *common]


DESCRIPTIONS = {
    "menu": "Added to your applications menu", "desktop": "Desktop shortcut created",
    "terminal": "Run  jace-passwords  from a terminal", "appstream": "App center info registered",
    "startmenu": "Added to the Start menu", "apps": "Listed in Windows \"Installed apps\"",
    "dock": "Added to the Dock", "unquarantine": "Removed the downloaded-from-internet flag",
    "applications": "Added to Launchpad and Spotlight", "autostart": "Starts in the tray when you sign in",
}


def default_dir() -> Path:
    if IS_WIN:
        return Path(os.environ.get("LOCALAPPDATA", HOME / "AppData" / "Local")) / "Programs" / APP_NAME
    if IS_MAC:
        return Path("/Applications") if os.access("/Applications", os.W_OK) else HOME / "Applications"
    return HOME / "Applications"


def install(target_dir: Path, opts: dict, status=print) -> Path:
    target_dir = Path(target_dir).expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    if IS_WIN:
        path, parts = _win_install(target_dir, opts, status)
    elif IS_MAC:
        path, parts = _mac_install(target_dir, opts, status)
    else:
        path, parts = _linux_install(target_dir, opts, status)
    if opts.get("autostart"):
        status("Starting with your computer")
        set_autostart(True, path)
        parts.append("autostart")
    write_private(record_path(), json.dumps({"path": str(path), "version": APP_VERSION, "parts": parts}))
    status("Done")
    return path


def uninstall(purge: bool = False, status=print) -> None:
    path = installed_path()
    set_autostart(False)
    if IS_WIN:
        _win_uninstall(path)
    elif IS_MAC:
        _mac_uninstall(path)
    else:
        _linux_uninstall(path)
    record_path().unlink(missing_ok=True)
    if purge:
        status("Deleting your vault from this computer")
        shutil.rmtree(data_dir(), ignore_errors=True)


def relaunch(path: Path, *args: str) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("APPIMAGE", "APPDIR", "ARGV0", "OWD", "_MEIPASS2")}
    env.pop("LD_LIBRARY_PATH", None)
    kw = {"close_fds": True, "env": env}
    if IS_WIN:
        kw["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        kw["cwd"] = str(path.parent)
    else:
        kw["start_new_session"] = True
    if IS_MAC:
        subprocess.Popen(["open", "-n", str(path), "--args", *args])
    else:
        subprocess.Popen(launch_command(path, *args), **kw)


# ---- start on sign-in -----------------------------------------------------------------------

def autostart_enabled() -> bool:
    if IS_WIN:
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
                winreg.QueryValueEx(k, APP_NAME)
                return True
        except OSError:
            return False
    return _autostart_file().exists()


def _autostart_file() -> Path:
    if IS_MAC:
        return HOME / "Library" / "LaunchAgents" / f"{APP_ID}.plist"
    return Path(os.environ.get("XDG_CONFIG_HOME") or HOME / ".config") / "autostart" / f"{APP_ID}.desktop"


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def set_autostart(on: bool, path: Path | None = None) -> None:
    path = path or installed_path() or running_package()
    if IS_WIN:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            if on and path:
                winreg.SetValueEx(k, APP_NAME, 0, winreg.REG_SZ, f'"{path}" --background')
            else:
                try:
                    winreg.DeleteValue(k, APP_NAME)
                except OSError:
                    pass
        return
    f = _autostart_file()
    if not on or not path:
        f.unlink(missing_ok=True)
        return
    f.parent.mkdir(parents=True, exist_ok=True)
    if IS_MAC:
        import plistlib
        f.write_bytes(plistlib.dumps({"Label": APP_ID, "RunAtLoad": True,
                                      "ProgramArguments": launch_command(path, "--background")}))
    else:
        f.write_text(_desktop_entry(path, autostart=True))


# ---- Linux (AppImage) -----------------------------------------------------------------------

DATA_HOME = Path(os.environ.get("XDG_DATA_HOME") or HOME / ".local" / "share")
MENU_FILE = DATA_HOME / "applications" / f"{APP_ID}.desktop"
ICON_FILE = DATA_HOME / "icons" / "hicolor" / "256x256" / "apps" / f"{APP_ID}.png"
METAINFO_FILE = DATA_HOME / "metainfo" / f"{APP_ID}.metainfo.xml"
BIN_LINK = HOME / ".local" / "bin" / "jace-passwords"
APPIMAGE_NAME = "JacePasswords.AppImage"
NO_AIL = "APPIMAGELAUNCHER_DISABLE=1"  # keeps AppImageLauncher from intercepting us (see Jace Launcher)


def desktop_dir() -> Path:
    try:
        out = subprocess.run(["xdg-user-dir", "DESKTOP"], capture_output=True, text=True, timeout=5).stdout.strip()
        if out and Path(out) != HOME:
            return Path(out)
    except (OSError, subprocess.SubprocessError):
        pass
    return HOME / "Desktop"


def _desktop_entry(exe: Path, autostart=False) -> str:
    args = "--background" if autostart else "%U"
    return ("[Desktop Entry]\nType=Application\n"
            f"Name={APP_NAME}\nGenericName=Password Manager\n"
            "Comment=Passwords, passkeys, 2FA codes and cards, end-to-end encrypted with your Jace account\n"
            f'Exec=env {NO_AIL} "{exe}" {args}\nIcon={APP_ID}\nTerminal=false\n'
            "Categories=Utility;Security;\nKeywords=password;passkey;2fa;totp;vault;autofill;jace;\n"
            f"StartupWMClass={APP_ID}\n"
            + ("X-GNOME-Autostart-enabled=true\nNoDisplay=true\n" if autostart else
               "Actions=uninstall;\n\n"
               f"[Desktop Action uninstall]\nName=Uninstall Jace Passwords\n"
               f'Exec=env {NO_AIL} "{exe}" --uninstall-gui\n'))


def metainfo() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<component type="desktop-application">
  <id>{APP_ID}</id>
  <name>{APP_NAME}</name>
  <summary>Password manager with passkeys, 2FA codes and autofill, synced with your Jace account</summary>
  <developer id="io.github.okjace"><name>{AUTHOR}</name></developer>
  <url type="homepage">{GITHUB_URL}</url>
  <metadata_license>CC0-1.0</metadata_license>
  <project_license>MIT</project_license>
  <description>
    <p>Jace Passwords keeps your logins, passkeys, two-factor codes, credit and debit cards, notes and
       identities in one end-to-end encrypted vault, and fills them in for you in your browser.</p>
    <ul>
      <li>Passkeys and built-in 2FA codes</li>
      <li>Password generator, Watchtower security checks and Travel Mode</li>
      <li>Syncs with your Jace account; Jace only ever sees ciphertext</li>
    </ul>
  </description>
  <launchable type="desktop-id">{APP_ID}.desktop</launchable>
  <categories><category>Utility</category><category>Security</category></categories>
  <content_rating type="oars-1.1"/>
  <releases><release version="{APP_VERSION}"/></releases>
</component>
"""


def _write(path: Path, text: str, executable=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if executable:
        path.chmod(0o755)


def _refresh_menus():
    for cmd in (["update-desktop-database", str(MENU_FILE.parent)],
                ["gtk-update-icon-cache", "-q", "-t", str(DATA_HOME / "icons" / "hicolor")]):
        try:
            subprocess.run(cmd, capture_output=True, timeout=20)
        except (OSError, subprocess.SubprocessError):
            pass


def _linux_install(target_dir: Path, opts: dict, status):
    src = running_package()
    if not src:
        raise RuntimeError("Run the AppImage to install Jace Passwords.")
    dst = target_dir / APPIMAGE_NAME
    if src.resolve() != dst.resolve():
        status(f"Copying Jace Passwords to {target_dir}")
        tmp = dst.with_suffix(".installing")
        shutil.copy2(src, tmp)
        tmp.chmod(0o755)
        tmp.replace(dst)
    parts = []
    ICON_FILE.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(ICON_PNG, ICON_FILE)
    if opts.get("menu"):
        status("Adding to the applications menu")
        _write(MENU_FILE, _desktop_entry(dst), executable=True)
        parts.append("menu")
    if opts.get("desktop"):
        status("Creating a desktop shortcut")
        link = desktop_dir() / f"{APP_ID}.desktop"
        _write(link, _desktop_entry(dst), executable=True)
        try:  # GNOME: mark it trusted so it isn't shown as "untrusted launcher"
            subprocess.run(["gio", "set", str(link), "metadata::trusted", "true"], capture_output=True, timeout=10)
        except (OSError, subprocess.SubprocessError):
            pass
        parts.append("desktop")
    if opts.get("terminal"):
        status("Adding the 'jace-passwords' command")
        BIN_LINK.unlink(missing_ok=True)
        _write(BIN_LINK, f'#!/bin/sh\nexec env {NO_AIL} "{dst}" "$@"\n', executable=True)
        parts.append("terminal")
    if opts.get("appstream"):
        status("Registering with app centers")
        _write(METAINFO_FILE, metainfo())
        parts.append("appstream")
    _refresh_menus()
    return dst, parts


def _linux_uninstall(path: Path | None):
    for f in (MENU_FILE, desktop_dir() / f"{APP_ID}.desktop", BIN_LINK, METAINFO_FILE, ICON_FILE):
        if f.is_symlink() or f.exists():
            f.unlink()
    if path and path.is_file() and path.name == APPIMAGE_NAME:
        path.unlink()
    _refresh_menus()


# ---- Windows (.exe) -------------------------------------------------------------------------

EXE_NAME = "JacePasswords.exe"
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\JacePasswords"
NO_WINDOW = 0x08000000


def _known_folder(csidl: int) -> Path:
    import ctypes
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.shell32.SHGetFolderPathW(None, csidl, None, 0, buf)
    return Path(buf.value)


def _win_shortcuts() -> list[Path]:
    return [_known_folder(0x02) / f"{APP_NAME}.lnk", _known_folder(0x10) / f"{APP_NAME}.lnk"]


def _make_shortcut(lnk: Path, exe: Path):
    q = lambda p: str(p).replace("'", "''")  # noqa: E731
    ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{q(lnk)}');$s.TargetPath='{q(exe)}';"
          f"$s.WorkingDirectory='{q(exe.parent)}';$s.IconLocation='{q(exe)},0';$s.Description='{APP_NAME}';$s.Save()")
    lnk.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", ps],
                   check=True, creationflags=NO_WINDOW, capture_output=True)


def _copy_tree(src: Path, dst: Path, status, skip=None):
    files = [f for f in src.rglob("*") if f.is_file() and not (skip and f.relative_to(src).parts[0] == skip)]
    for i, f in enumerate(files):
        if i % 250 == 0:
            status(f"Copying files… {i * 100 // max(1, len(files))}%")
        out = dst / f.relative_to(src)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, out)


def _win_install(target_dir: Path, opts: dict, status):
    exe = target_dir / EXE_NAME
    if is_setup_build():
        meipass = Path(sys._MEIPASS)
        internal, stage, old = target_dir / "_internal", target_dir / "_internal.new", target_dir / "_internal.old"
        shutil.rmtree(stage, ignore_errors=True)
        _copy_tree(meipass, stage, status, skip="jp_setup")
        shutil.rmtree(old, ignore_errors=True)
        if internal.exists():
            internal.rename(old)
        stage.rename(internal)
        shutil.copy2(meipass / "jp_setup" / EXE_NAME, exe)
        shutil.rmtree(old, ignore_errors=True)
    elif running_package() and running_package().parent.resolve() != target_dir.resolve():
        _copy_tree(running_package().parent, target_dir, status)
    parts = []
    sm, dt = _win_shortcuts()
    if opts.get("startmenu"):
        status("Adding to the Start menu")
        _make_shortcut(sm, exe)
        parts.append("startmenu")
    if opts.get("desktop"):
        status("Creating a desktop shortcut")
        _make_shortcut(dt, exe)
        parts.append("desktop")
    if opts.get("apps"):
        status("Adding to Installed apps")
        import winreg
        size = sum(f.stat().st_size for f in target_dir.rglob("*") if f.is_file()) // 1024
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY) as k:
            for name, val in (("DisplayName", APP_NAME), ("DisplayVersion", APP_VERSION), ("Publisher", AUTHOR),
                              ("DisplayIcon", f'"{exe}",0'), ("InstallLocation", str(target_dir)),
                              ("UninstallString", f'"{exe}" --uninstall-gui'),
                              ("QuietUninstallString", f'"{exe}" --uninstall'), ("URLInfoAbout", GITHUB_URL)):
                winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
            for name, val in (("NoModify", 1), ("NoRepair", 1), ("EstimatedSize", size)):
                winreg.SetValueEx(k, name, 0, winreg.REG_DWORD, val)
        parts.append("apps")
    return exe, parts


def _after_exit(command: str):
    subprocess.Popen(f"cmd /c timeout /t 3 /nobreak >nul & {command}", cwd=os.environ.get("TEMP", "C:\\"),
                     creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | NO_WINDOW,
                     close_fds=True)


def _win_uninstall(path: Path | None):
    import winreg
    for lnk in _win_shortcuts():
        lnk.unlink(missing_ok=True)
    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, UNINSTALL_KEY)
    except OSError:
        pass
    if path:
        _after_exit(f'rmdir /s /q "{path.parent}"')


def delete_downloaded_setup_after_exit():
    if is_setup_build():
        _after_exit(f'del /f /q "{sys.executable}"')


# ---- macOS (.app) ---------------------------------------------------------------------------

MAC_APP = f"{APP_NAME}.app"
MAC_DESKTOP_LINK = HOME / "Desktop" / APP_NAME
LSREGISTER = ("/System/Library/Frameworks/CoreServices.framework/Frameworks/"
              "LaunchServices.framework/Support/lsregister")


def _quiet(cmd):
    return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _dock_add(app: Path):
    url = app.as_uri().rstrip("/") + "/"
    out = subprocess.run(["defaults", "read", "com.apple.dock", "persistent-apps"], capture_output=True, text=True).stdout
    if app.name.replace(" ", "%20") in out:
        return
    tile = (f"<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>{url}</string>"
            f"<key>_CFURLStringType</key><integer>15</integer></dict></dict></dict>")
    _quiet(["defaults", "write", "com.apple.dock", "persistent-apps", "-array-add", tile])
    _quiet(["killall", "Dock"])


def _dock_remove():
    import plistlib
    import time
    for _ in range(5):
        raw = subprocess.run(["defaults", "export", "com.apple.dock", "-"], capture_output=True).stdout
        prefs = plistlib.loads(raw) if raw else {}
        apps = prefs.get("persistent-apps", [])
        keep = [t for t in apps if not t.get("tile-data", {}).get("file-data", {}).get("_CFURLString", "")
                .rstrip("/").endswith(MAC_APP.replace(" ", "%20"))]
        if len(keep) == len(apps):
            return
        prefs["persistent-apps"] = keep
        subprocess.run(["defaults", "import", "com.apple.dock", "-"], input=plistlib.dumps(prefs), check=False)
        _quiet(["killall", "Dock"])
        time.sleep(2)


def _mac_install(target_dir: Path, opts: dict, status):
    src = running_package()
    if not src:
        raise RuntimeError(f"Open {MAC_APP} to install it.")
    dst = target_dir / MAC_APP
    if src.resolve() != dst.resolve():
        status(f"Copying Jace Passwords to {target_dir}")
        tmp = target_dir / f".{MAC_APP}.installing"
        shutil.rmtree(tmp, ignore_errors=True)
        subprocess.run(["ditto", str(src), str(tmp)], check=True)
        if dst.exists():
            shutil.rmtree(dst)
        tmp.rename(dst)
    parts = []
    if opts.get("unquarantine"):
        status("Removing the downloaded-from-internet flag")
        _quiet(["xattr", "-dr", "com.apple.quarantine", str(dst)])
        parts.append("unquarantine")
    _quiet([LSREGISTER, "-f", str(dst)])
    parts.append("applications")
    if opts.get("dock"):
        status("Adding to the Dock")
        _dock_add(dst)
        parts.append("dock")
    if opts.get("desktop"):
        status("Creating a desktop shortcut")
        if MAC_DESKTOP_LINK.is_symlink() or MAC_DESKTOP_LINK.exists():
            MAC_DESKTOP_LINK.unlink()
        MAC_DESKTOP_LINK.parent.mkdir(parents=True, exist_ok=True)
        MAC_DESKTOP_LINK.symlink_to(dst)
        parts.append("desktop")
    return dst, parts


def _mac_uninstall(path: Path | None):
    _dock_remove()
    if MAC_DESKTOP_LINK.is_symlink() or MAC_DESKTOP_LINK.exists():
        MAC_DESKTOP_LINK.unlink()
    if path and path.exists() and "/AppTranslocation/" not in str(path):
        subprocess.Popen(["/bin/sh", "-c", 'sleep 2; rm -rf "$0"', str(path)], start_new_session=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
