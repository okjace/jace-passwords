"""Jace's palette (okjace/Jace app/globals.css) for the native parts: wizard, dialogs, tray menu."""
QSS = """
* { font-family: Geist, "Segoe UI", system-ui, sans-serif; font-size: 13px; }
QWidget { background: #111317; color: #e6e8eb; }
QWizard, QDialog { background: #111317; }
QLabel#title { font-size: 20px; font-weight: 700; }
QLabel#muted { color: #8b919c; }
QLabel#ok { color: #3ddc84; }
QLineEdit, QPlainTextEdit { background: #1c1f26; border: 1px solid #2a2f38; border-radius: 8px; padding: 7px 10px;
                            selection-background-color: #3ddc84; selection-color: #0c1410; }
QLineEdit:focus { border-color: #3ddc84; }
QPushButton { background: #1c1f26; border: 1px solid #2a2f38; border-radius: 9px; padding: 8px 16px; font-weight: 600; }
QPushButton:hover { border-color: #3ddc84; }
QPushButton:default, QPushButton#primary { background: #3ddc84; color: #0c1410; border: 0; }
QPushButton:default:hover, QPushButton#primary:hover { background: #5ae69a; }
QPushButton:disabled { color: #5d6470; background: #1c1f26; }
QCheckBox { spacing: 10px; padding: 4px 0; }
QCheckBox::indicator { width: 18px; height: 18px; border-radius: 5px; border: 1px solid #2a2f38; background: #1c1f26; }
QCheckBox::indicator:checked { background: #3ddc84; border-color: #3ddc84; }
QProgressBar { background: #1c1f26; border: 0; border-radius: 4px; height: 8px; text-align: center; }
QProgressBar::chunk { background: #3ddc84; border-radius: 4px; }
QMenu { background: #1c1f26; border: 1px solid #2a2f38; padding: 6px; border-radius: 10px; }
QMenu::item { padding: 7px 18px; border-radius: 6px; }
QMenu::item:selected { background: #23272f; }
QMenu::separator { height: 1px; background: #2a2f38; margin: 5px 8px; }
"""
