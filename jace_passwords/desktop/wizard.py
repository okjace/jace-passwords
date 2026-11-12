"""Setup wizard (shown the first time the downloaded app runs, or with --install), like Jace Launcher's."""
import shutil
import threading
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QPixmap
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
                               QPushButton, QVBoxLayout, QWizard, QWizardPage)

from .. import APP_NAME, APP_VERSION, GITHUB_URL
from . import install

IS_WIN, IS_MAC = install.IS_WIN, install.IS_MAC


def _muted(text):
    lab = QLabel(text)
    lab.setObjectName("muted")
    lab.setWordWrap(True)
    lab.setOpenExternalLinks(True)
    return lab


class WelcomePage(QWizardPage):
    def __init__(self, upgrade: bool):
        super().__init__()
        lay = QVBoxLayout(self)
        row = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(QPixmap(str(install.ICON_PNG)).scaled(88, 88, Qt.AspectRatioMode.KeepAspectRatio,
                                                             Qt.TransformationMode.SmoothTransformation))
        row.addWidget(icon, 0, Qt.AlignmentFlag.AlignTop)
        col = QVBoxLayout()
        title = QLabel(f"{'Update' if upgrade else 'Welcome to'} {APP_NAME}")
        title.setObjectName("title")
        col.addWidget(title)
        where = ("add it to the Dock, Launchpad and your desktop" if IS_MAC else
                 "add it to the Start menu and your desktop, and list it in \"Installed apps\"" if IS_WIN else
                 "add it to your applications menu, desktop and app centers")
        text = QLabel(
            f"<p>This sets up <b>{APP_NAME} {APP_VERSION}</b>: passwords, passkeys, 2FA codes and cards in one "
            "end-to-end encrypted vault, synced with your Jace account.</p>"
            f"<p>Next, choose where to install it. Setup will {where}, and can start it in the background "
            "when you sign in so the browser extension can always autofill.</p>"
            + ("<p>A version is already installed; it will be replaced. <b>Your vault is kept.</b></p>" if upgrade else ""))
        text.setWordWrap(True)
        col.addWidget(text)
        row.addLayout(col, 1)
        lay.addLayout(row)
        lay.addStretch()
        lay.addWidget(_muted("Jace Passwords needs to be installed before you can use it."))


class LocationPage(QWizardPage):
    def __init__(self):
        super().__init__()
        self.setTitle("Where to install, and shortcuts")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel("Install Jace Passwords to:"))
        row = QHBoxLayout()
        current = install.installed_path()
        start = current.parent if current else install.default_dir()
        self.path = QLineEdit(str(start))
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        row.addWidget(self.path, 1)
        row.addWidget(browse)
        lay.addLayout(row)
        lay.addSpacing(10)
        self.boxes = {}
        for key, label, default in install.options():
            cb = QCheckBox(label)
            cb.setChecked(default)
            self.boxes[key] = cb
            lay.addWidget(cb)
        lay.addSpacing(6)
        lay.addWidget(_muted("Your vault isn't stored here: it lives in your user data folder and is never "
                             "touched by installing, updating or uninstalling."))
        lay.addStretch()

    def chosen(self) -> dict:
        return {k: cb.isChecked() for k, cb in self.boxes.items()}

    def _browse(self):
        d = QFileDialog.getExistingDirectory(self, "Install location", self.path.text())
        if d:
            self.path.setText(d)

    def validatePage(self):
        p = Path(self.path.text()).expanduser()
        try:
            p.mkdir(parents=True, exist_ok=True)
            probe = p / ".jp-write-test"
            probe.write_text("x")
            probe.unlink()
        except OSError as e:
            QMessageBox.warning(self, APP_NAME, f"Can't install to {p}:\n{e}")
            return False
        free = shutil.disk_usage(p).free // (1024 * 1024)
        if free < 400:
            QMessageBox.warning(self, APP_NAME, f"Only {free} MB free there; Jace Passwords needs about 400 MB.")
            return False
        return True


class _Bridge(QObject):
    status = Signal(str)
    finished = Signal(str, str)  # path, error


class InstallPage(QWizardPage):
    def __init__(self, loc: LocationPage):
        super().__init__()
        self.loc = loc
        self.setTitle("Installing")
        lay = QVBoxLayout(self)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        lay.addWidget(self.log)
        self.done = False
        self.path: Path | None = None
        self.bridge = _Bridge()
        self.bridge.status.connect(self.log.appendPlainText)
        self.bridge.finished.connect(self._finished)

    def initializePage(self):
        self.done = False
        target, opts = Path(self.loc.path.text()).expanduser(), self.loc.chosen()

        def work():
            try:
                path = install.install(target, opts, status=self.bridge.status.emit)
                self.bridge.finished.emit(str(path), "")
            except Exception as e:  # noqa: BLE001
                self.bridge.finished.emit("", str(e))
        threading.Thread(target=work, daemon=True).start()

    def _finished(self, path, error):
        if error:
            self.log.appendPlainText(f"\nSomething went wrong: {error}")
            QMessageBox.critical(self, APP_NAME, f"Installing failed:\n{error}")
            return
        self.path = Path(path)
        self.done = True
        self.completeChanged.emit()
        self.wizard().next()

    def isComplete(self):
        return self.done


class FinishPage(QWizardPage):
    def __init__(self, inst: InstallPage):
        super().__init__()
        self.inst = inst
        self.setTitle("Jace Passwords is installed 🎉")
        lay = QVBoxLayout(self)
        self.summary = QLabel()
        self.summary.setWordWrap(True)
        lay.addWidget(self.summary)
        lay.addSpacing(8)
        lay.addWidget(_muted(
            "<b>Autofill in your browser:</b> get the Jace Passwords extension from the "
            f"<a style='color:#3ddc84' href='{GITHUB_URL}/releases/latest'>latest release</a> "
            "(Jace Browser / Firefox: the signed .xpi; Chrome, Edge, Brave: the -chrome.zip), "
            "then pair it in Settings → Browser extension."))
        lay.addStretch()
        self.open_now = QCheckBox("Open Jace Passwords now")
        self.open_now.setChecked(True)
        lay.addWidget(self.open_now)

    def initializePage(self):
        parts = install.install_record().get("parts", [])
        items = "".join(f"<li>{install.DESCRIPTIONS.get(p, p)}</li>" for p in parts)
        self.summary.setText(f"<p>Installed to <code>{self.inst.path}</code></p><ul>{items}</ul>")


class SetupWizard(QWizard):
    def __init__(self, upgrade=False):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} Setup")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.NoBackButtonOnLastPage, True)
        self.setOption(QWizard.WizardOption.NoCancelButtonOnLastPage, True)
        self.setMinimumSize(620, 460)
        self.addPage(WelcomePage(upgrade))
        self.loc = LocationPage()
        self.addPage(self.loc)
        self.inst = InstallPage(self.loc)
        self.addPage(self.inst)
        self.finish = FinishPage(self.inst)
        self.addPage(self.finish)
        self.setButtonText(QWizard.WizardButton.CommitButton, "Install")
        self.loc.setCommitPage(True)

    def installed(self) -> Path | None:
        return self.inst.path

    def open_after(self) -> bool:
        return self.finish.open_now.isChecked()


def confirm_uninstall(parent=None) -> tuple[bool, bool]:
    """(uninstall?, also delete the vault?)"""
    box = QMessageBox(parent)
    box.setWindowTitle(f"Uninstall {APP_NAME}")
    box.setIcon(QMessageBox.Icon.Question)
    box.setText(f"Uninstall {APP_NAME} from this computer?")
    box.setInformativeText("Your vault stays on this computer (and on your Jace account if you sync) unless you "
                           "tick the box below.")
    purge = QCheckBox("Also delete my vault from this computer")
    box.setCheckBox(purge)
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
    box.button(QMessageBox.StandardButton.Yes).setText("Uninstall")
    ok = box.exec() == QMessageBox.StandardButton.Yes
    if ok and purge.isChecked():
        sure = QMessageBox.warning(parent, APP_NAME, "Delete your vault from this computer? If it isn't synced to "
                                   "Jace and you have no backup, everything in it is gone for good.",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                   QMessageBox.StandardButton.No)
        return True, sure == QMessageBox.StandardButton.Yes
    return ok, False
