#!/usr/bin/env bash
# Build dist/JacePasswords-<ver>-x86_64.AppImage (like Jace Launcher's build)
#   1. PyInstaller bundles Python + PySide6 + the app into a folder
#   2. lay out an AppDir (desktop file, icon, AppStream metadata)
#   3. appimagetool turns that into one AppImage file
# Uses .venv/bin/python (python3 -m venv .venv && .venv/bin/pip install -r requirements-desktop.txt pyinstaller)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
PY="${PYTHON:-$ROOT/.venv/bin/python}"
APP_ID="io.github.okjace.JacePasswords"
VERSION="$("$PY" -c 'import jace_passwords as j; print(j.APP_VERSION)')"
BUILD="$ROOT/build/appimage"
APPDIR="$BUILD/AppDir"
TOOL="$ROOT/packaging/tools/appimagetool"

"$PY" -m pip install -q pyinstaller
if [ ! -x "$TOOL" ]; then
  mkdir -p "$(dirname "$TOOL")"
  curl -sSL -o "$TOOL" https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage
  chmod +x "$TOOL"
fi

echo "==> PyInstaller"
rm -rf "$BUILD"
"$PY" -m PyInstaller --noconfirm --clean --log-level WARN \
  --name jace-passwords --windowed \
  --distpath "$BUILD/dist" --workpath "$BUILD/work" --specpath "$BUILD" \
  --paths "$ROOT" \
  --add-data "$ROOT/jace_passwords/web:jace_passwords/web" \
  --add-data "$ROOT/jace_passwords/desktop/icon.png:jace_passwords/desktop" \
  --hidden-import PySide6.QtWebEngineWidgets --hidden-import PySide6.QtWebEngineCore \
  --collect-data certifi \
  --exclude-module tkinter --exclude-module _tkinter \
  "$ROOT/packaging/entry.py"

# Qt >= 6.5 needs libxcb-cursor on X11 but many distros don't install it: ship it next to Qt.
QTLIB="$(find "$BUILD/dist/jace-passwords" -type d -path '*PySide6/Qt/lib' | head -1)"
XCBC="$(ldconfig -p | awk '/libxcb-cursor.so.0 /{p=$NF} END{print p}')"
if [ -n "$XCBC" ] && [ -n "$QTLIB" ]; then cp -L "$XCBC" "$QTLIB/libxcb-cursor.so.0"; else echo "warning: libxcb-cursor0 not bundled"; fi

# Never ship libraries that must match the user's graphics drivers / system (see Jace Launcher).
for lib in libstdc++.so.6 libgcc_s.so.1 libgbm.so.1 libfontconfig.so.1 libfreetype.so.6 libexpat.so.1 \
           libglib-2.0.so.0 libgio-2.0.so.0 libgobject-2.0.so.0 libgmodule-2.0.so.0 libdbus-1.so.3; do
  find "$BUILD/dist/jace-passwords" -name "$lib" -delete
done

echo "==> AppDir"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/metainfo" \
         "$APPDIR/usr/share/icons/hicolor/256x256/apps"
cp -a "$BUILD/dist/jace-passwords" "$APPDIR/usr/bin/"
cp packaging/AppRun "$APPDIR/AppRun"
chmod +x "$APPDIR/AppRun"
cp packaging/icons/icon.png "$APPDIR/$APP_ID.png"
cp packaging/icons/icon.png "$APPDIR/usr/share/icons/hicolor/256x256/apps/$APP_ID.png"
ln -sf "$APP_ID.png" "$APPDIR/.DirIcon"
cat > "$APPDIR/$APP_ID.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Jace Passwords
GenericName=Password Manager
Comment=Passwords, passkeys, 2FA codes and cards, end-to-end encrypted with your Jace account
Exec=jace-passwords %U
Icon=$APP_ID
Terminal=false
Categories=Utility;Security;
Keywords=password;passkey;2fa;totp;vault;autofill;jace;
X-AppImage-Integrate=false
DESKTOP
cp "$APPDIR/$APP_ID.desktop" "$APPDIR/usr/share/applications/"
"$PY" -c "from jace_passwords.desktop.install import metainfo; print(metainfo(), end='')" \
  > "$APPDIR/usr/share/metainfo/$APP_ID.metainfo.xml"

echo "==> appimagetool"
mkdir -p dist
OUT="$ROOT/dist/JacePasswords-$VERSION-x86_64.AppImage"
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$TOOL" --no-appstream "$APPDIR" "$OUT"
echo
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"
echo "Run it once to open the setup wizard, or:  $OUT --install --yes"
