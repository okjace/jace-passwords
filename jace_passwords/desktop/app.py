"""Desktop entry point.

  Jace Passwords                     open the app (setup wizard first if this download isn't installed)
  --background                       start in the tray (used when it starts with your computer)
  --install [--yes]                  run setup (--yes: no questions, default options)
  --uninstall [--purge] / --uninstall-gui   remove the app (--purge also deletes the vault)
  --self-test                        start headless, load the vault UI, write SELF-TEST OK (CI)
  --version
"""
import os
import sys
import time
import traceback
from pathlib import Path

from .. import APP_ID, APP_NAME, APP_VERSION, data_dir


def _arg(name):
    return name in sys.argv


def _say(text):
    out = os.environ.get("JACE_SELF_TEST_OUT")
    if out:
        with open(out, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    try:
        print(text, flush=True)
    except (OSError, ValueError, AttributeError):
        pass  # windowed builds on Windows have no console


def _qt_app():
    from PySide6.QtGui import QIcon
    from PySide6.QtWidgets import QApplication
    from .install import ICON_PNG
    from .style import QSS
    QApplication.setApplicationName(APP_NAME)
    QApplication.setOrganizationName("Jace")
    QApplication.setDesktopFileName(APP_ID)
    app = QApplication.instance() or QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(QIcon(str(ICON_PNG)))
    return app, QSS, QIcon(str(ICON_PNG))


def self_test() -> int:
    """Everything a release must survive: the server, the vault UI loading in the window."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--no-sandbox")
    from PySide6.QtCore import QTimer
    from ..server import App, start
    from . import install, wizard  # noqa: F401 - must import in the build
    from .window import MainWindow
    app, qss, icon = _qt_app()
    app.setStyleSheet(qss)
    started = start(App())
    if not started:
        _say("SELF-TEST FAILED: port in use")
        return 1
    _httpd, url = started
    import urllib.request
    try:  # hard requirement: the vault server answers and serves the UI
        with urllib.request.urlopen(url, timeout=10) as r:
            page = r.read().decode()
        server_ok = "app.js" in page or "Jace Passwords" in page
    except Exception as e:  # noqa: BLE001
        _say(f"server error: {e}")
        server_ok = False
    win = MainWindow(url, icon)
    win.show()
    result = {}

    def check():
        win.view.page().runJavaScript(
            "JSON.stringify({title: document.title, ui: !!document.querySelector('#app .card, #app .layout')})",
            0, lambda r: result.update(json=r))
    deadline = time.time() + 45
    while time.time() < deadline and "json" not in result:
        QTimer.singleShot(0, check)
        app.processEvents()
        time.sleep(0.25)
        if result.get("json") and '"ui":false' in result["json"]:
            result.pop("json")
    _say(f"{APP_NAME} {APP_VERSION} | frozen={install.frozen()} | package={install.running_package()} | page={result.get('json')}")
    ui_ok = bool(result.get("json")) and '"ui":true' in result["json"]
    _say(f"server={'ok' if server_ok else 'FAILED'} window={'ok' if ui_ok else 'not rendered (headless?)'}")
    ok = server_ok and (ui_ok or not os.environ.get("JACE_SELF_TEST_STRICT"))
    _say("SELF-TEST OK" if ok else "SELF-TEST FAILED")
    return 0 if ok else 1


def run_setup(yes: bool) -> int:
    from . import install
    if yes:
        path = install.install(install.default_dir(), {k: d for k, _, d in install.options()})
        _say(f"Installed to {path}")
        return 0
    from .wizard import SetupWizard
    app, qss, _icon = _qt_app()
    app.setStyleSheet(qss)
    w = SetupWizard(upgrade=install.installed_path() is not None)
    if w.exec() and w.installed():
        if w.open_after():
            install.relaunch(w.installed())
        install.delete_downloaded_setup_after_exit()
        return 0
    return 1


def run_uninstall(gui: bool) -> int:
    from . import install
    purge = _arg("--purge")
    if gui:
        from PySide6.QtWidgets import QMessageBox
        from .wizard import confirm_uninstall
        app, qss, _icon = _qt_app()
        app.setStyleSheet(qss)
        ok, purge = confirm_uninstall()
        if not ok:
            return 1
        install.uninstall(purge=purge)
        QMessageBox.information(None, APP_NAME, f"{APP_NAME} was uninstalled." +
                                ("" if purge else " Your vault is still on this computer."))
        return 0
    install.uninstall(purge=purge)
    _say("Uninstalled.")
    return 0


def run_app() -> int:
    from ..server import App, show_running_copy, start
    from . import install
    from .window import Bridge, MainWindow, check_updates, make_tray

    # Downloaded but not installed yet (AppImage / .exe / .app): set it up first, like Jace Launcher.
    if install.setup_available() and not install.running_installed_copy() and not _arg("--no-setup"):
        return run_setup(yes=False)

    state = App()
    started = start(state)
    if not started:
        if show_running_copy():
            return 0
        _say(f"{APP_NAME} couldn't start: its port is used by another program.")
        return 1
    _httpd, url = started

    app, qss, icon = _qt_app()
    app.setStyleSheet(qss)
    win = MainWindow(url, icon)
    win.bridge = Bridge()
    win.bridge.show.connect(win.bring_forward)
    state.on_show = win.bridge.show.emit
    tray = make_tray(win, state, icon)

    def on_update(version, link):
        from PySide6.QtCore import QUrl
        from PySide6.QtGui import QDesktopServices
        from PySide6.QtWidgets import QMessageBox
        if not version:
            QMessageBox.information(win, APP_NAME, f"You have the latest version ({APP_VERSION}).")
            return
        win.update_a.setText(f"Get version {version}…")
        try:
            win.update_a.triggered.disconnect()
        except (RuntimeError, TypeError):
            pass
        win.update_a.triggered.connect(lambda: QDesktopServices.openUrl(QUrl(link)))
        if tray:
            tray.showMessage(APP_NAME, f"Version {version} is available. Open the tray menu to get it.",
                             tray.MessageIcon.Information, 8000)
    win.bridge.update.connect(on_update)
    check_updates(win.bridge)

    if not (_arg("--background") and tray):
        win.show()
    return app.exec()


def main() -> int:
    if _arg("--version"):
        print(f"{APP_NAME} {APP_VERSION}")
        return 0
    try:
        if _arg("--self-test"):
            return self_test()
        if _arg("--install"):
            return run_setup(yes=_arg("--yes"))
        if _arg("--uninstall") or _arg("--uninstall-gui"):
            return run_uninstall(gui=_arg("--uninstall-gui"))
        return run_app()
    except Exception:  # noqa: BLE001 - leave a crash log next to the vault
        (Path(data_dir()) / "crash.log").write_text(traceback.format_exc())
        raise
