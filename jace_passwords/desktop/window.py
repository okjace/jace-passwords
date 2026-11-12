"""The app window (the vault UI in a web view) and the tray icon."""
import json
import tempfile
import threading
import urllib.request
from pathlib import Path

from PySide6.QtCore import QObject, QSettings, QUrl, Signal
from PySide6.QtGui import QAction, QDesktopServices, QIcon
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineSettings
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QApplication, QFileDialog, QMainWindow, QMenu, QSystemTrayIcon

from .. import APP_NAME, APP_VERSION, GITHUB_REPO, GITHUB_URL, HOST, JACE_URL, PORT
from . import install

APP_ORIGIN = f"http://{HOST}:{PORT}"


def _is_app(url: QUrl) -> bool:
    return url.scheme() == "http" and url.host() == HOST and url.port() == PORT


class Page(QWebEnginePage):
    """Keeps the window on the vault: other links open in your browser. Signing in to Jace
    happens in the window, and anything that sign-in needs (Jace, GitHub) is allowed."""

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):  # noqa: N802
        if not is_main_frame or _is_app(url) or url.scheme() in ("data", "blob", "about"):
            return True
        if _is_app(self.url()) and not url.toString().startswith(JACE_URL):
            QDesktopServices.openUrl(url)
            return False
        return True

    def createWindow(self, _type):  # noqa: N802 - target=_blank links -> your browser
        tmp = QWebEnginePage(self.profile(), self)

        def go(u):
            if u.isValid() and not u.isEmpty():
                QDesktopServices.openUrl(u)
                tmp.deleteLater()
        tmp.urlChanged.connect(go)
        return tmp


class Bridge(QObject):
    show = Signal()
    update = Signal(str, str)  # version, url


class MainWindow(QMainWindow):
    def __init__(self, launch_url: str, icon: QIcon):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setWindowIcon(icon)
        self.resize(1240, 820)
        self.setMinimumSize(420, 520)
        self.settings = QSettings("Jace", APP_NAME)
        geo = self.settings.value("geometry")
        if geo is not None:
            self.restoreGeometry(geo)
        self.quitting = False
        self.told_about_tray = bool(self.settings.value("toldAboutTray", False, bool))

        profile = QWebEngineProfile(self)  # off the record: nothing from the vault is cached on disk
        profile.downloadRequested.connect(self._download)
        self.view = QWebEngineView(self)
        page = Page(profile, self.view)
        s = page.settings()
        s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, True)
        s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanPaste, True)
        if hasattr(page, "permissionRequested"):  # Qt 6.8+
            page.permissionRequested.connect(self._permission)
        page.printRequested.connect(self._print)
        self.view.setPage(page)
        self.view.setUrl(QUrl(launch_url))
        self.setCentralWidget(self.view)

    # clipboard (copy password, 2FA code…) for the vault page only
    def _permission(self, perm):
        try:
            if _is_app(perm.origin()):
                perm.grant()
            else:
                perm.deny()
        except Exception:  # noqa: BLE001
            pass

    def _download(self, item):
        name = item.downloadFileName() or "jace-passwords-export"
        path, _ = QFileDialog.getSaveFileName(self, "Save", str(Path.home() / name))
        if not path:
            item.cancel()
            return
        item.setDownloadDirectory(str(Path(path).parent))
        item.setDownloadFileName(Path(path).name)
        item.accept()

    def _print(self):  # Emergency Kit -> PDF you can print or keep
        out = Path(tempfile.gettempdir()) / "Jace Passwords Emergency Kit.pdf"
        self.view.page().printToPdf(str(out))
        self.view.page().pdfPrintingFinished.connect(
            lambda p, ok: QDesktopServices.openUrl(QUrl.fromLocalFile(p)) if ok else None)

    def bring_forward(self):
        self.show()
        self.setWindowState(self.windowState() & ~self.windowState().WindowMinimized)
        self.raise_()
        self.activateWindow()

    def closeEvent(self, e):  # noqa: N802
        self.settings.setValue("geometry", self.saveGeometry())
        if self.quitting or not QSystemTrayIcon.isSystemTrayAvailable():
            e.accept()
            QApplication.quit()
            return
        e.ignore()
        self.hide()  # keep running in the tray so autofill keeps working
        if not self.told_about_tray and getattr(self, "tray", None):
            self.tray.showMessage(APP_NAME, "Still running in the tray so your browser can autofill. "
                                  "Right-click the icon to lock or quit.", QSystemTrayIcon.MessageIcon.Information, 6000)
            self.told_about_tray = True
            self.settings.setValue("toldAboutTray", True)


def make_tray(win: MainWindow, app_state, icon: QIcon) -> QSystemTrayIcon | None:
    if not QSystemTrayIcon.isSystemTrayAvailable():
        return None
    tray = QSystemTrayIcon(icon, win)
    tray.setToolTip(APP_NAME)
    menu = QMenu()
    open_a = QAction("Open Jace Passwords", menu)
    open_a.triggered.connect(win.bring_forward)
    lock_a = QAction("Lock", menu)
    lock_a.triggered.connect(lambda: (app_state.vault.lock(), tray.showMessage(APP_NAME, "Locked.",
                                                                             QSystemTrayIcon.MessageIcon.Information, 2000)))
    auto_a = QAction("Start when I sign in", menu)
    auto_a.setCheckable(True)
    can_autostart = bool(install.installed_path() or install.running_package())
    auto_a.setEnabled(can_autostart)
    auto_a.setChecked(can_autostart and install.autostart_enabled())
    auto_a.toggled.connect(lambda on: install.set_autostart(on))
    win.update_a = QAction("Check for updates", menu)
    win.update_a.triggered.connect(lambda: check_updates(win.bridge, manual=True))
    quit_a = QAction("Quit Jace Passwords", menu)

    def quit_all():
        win.quitting = True
        app_state.vault.lock()
        QApplication.quit()
    quit_a.triggered.connect(quit_all)
    for a in (open_a, lock_a, None, auto_a, win.update_a, None, quit_a):
        menu.addSeparator() if a is None else menu.addAction(a)
    tray.setContextMenu(menu)
    tray.activated.connect(lambda reason: win.bring_forward()
                           if reason in (QSystemTrayIcon.ActivationReason.Trigger,
                                         QSystemTrayIcon.ActivationReason.DoubleClick) else None)
    tray.show()
    win.tray = tray
    return tray


def _newer(a: str, b: str) -> bool:
    def parts(v):
        return tuple(int(x) if x.isdigit() else 0 for x in v.lstrip("v").split("."))
    return parts(a) > parts(b)


def check_updates(bridge: Bridge, manual=False):
    """Looks at the latest GitHub release; tells you if there's a newer version."""
    def run():
        try:
            req = urllib.request.Request(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                                         headers={"User-Agent": f"JacePasswords/{APP_VERSION}",
                                                  "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                rel = json.loads(r.read())
            tag = rel.get("tag_name", "")
            if _newer(tag, APP_VERSION):
                bridge.update.emit(tag.lstrip("v"), rel.get("html_url") or f"{GITHUB_URL}/releases/latest")
            elif manual:
                bridge.update.emit("", "")
        except Exception:  # noqa: BLE001 - offline is fine
            if manual:
                bridge.update.emit("", "")
    threading.Thread(target=run, daemon=True).start()
