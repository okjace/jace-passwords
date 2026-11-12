"""python3 -m jace_passwords [--browser] [--no-browser] [--version] [desktop flags, see desktop/app.py]

With PySide6 installed this opens the desktop app; otherwise (or with --browser) it serves
the vault UI and opens it in your web browser.
"""
import json
import sys
import webbrowser

from . import APP_NAME, APP_VERSION, HOST, PORT, data_dir


def browser_mode() -> int:
    from .server import App, serve
    if serve(App(), open_browser="--no-browser" not in sys.argv):
        return 0
    try:  # already running: open the running copy's window
        info = json.loads((data_dir() / "server.json").read_text())
        url = f"http://{HOST}:{info['port']}/?launch={info['launch']}"
        print(url) if "--no-browser" in sys.argv else webbrowser.open(url)
        return 0
    except (OSError, ValueError, KeyError):
        print(f"{APP_NAME} couldn't start: port {PORT} is already in use (maybe another copy using a "
              f"different data folder). Close it, or find it with:  ss -ltnp | grep {PORT}", file=sys.stderr)
        return 1


def main() -> int:
    if "--version" in sys.argv:
        print(f"{APP_NAME} {APP_VERSION}")
        return 0
    if "--browser" not in sys.argv and "--no-browser" not in sys.argv:
        try:
            import PySide6.QtWebEngineWidgets  # noqa: F401
        except ImportError:
            pass
        else:
            from .desktop.app import main as desktop_main
            return desktop_main()
    return browser_mode()


if __name__ == "__main__":
    sys.exit(main())
