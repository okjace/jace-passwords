# 🔐 Jace Passwords

A password manager tied to your **Jace account**. It's end-to-end encrypted and fills in your logins and passkeys for you.

## Features

| | |
|---|---|
| **Logins** | Username, password, multiple websites, notes, custom fields, tags, favorites, password history |
| **Passkeys** | Save and sign in with passkeys on any site. Each passkey is a P-256 key in your encrypted vault that syncs with your Jace account and works in every browser where you install the extension. Passkeys also show up in the username field's menu, and "Use another device" hands off to your phone or security key |
| **2FA codes** | Store the TOTP setup key (or `otpauth://` link, or read a QR screenshot) on the login itself. Live codes with a countdown ring, filled automatically on the 2FA page |
| **Sign in with…** | Record that a site uses *Sign in with Google / Apple / Microsoft / GitHub / Facebook / X / Discord / Jace* and which account you use |
| **Cards** | Credit & debit cards with brand detection, Luhn check, card visual, CVV & PIN hidden; autofill on checkout pages |
| **Secure notes, Identities, Email aliases** | Notes; name/address/phone autofill; plus-address aliases (`you+shop.ab12@gmail.com`) for each site, like Proton Pass |
| **Password generator** | Random (8–64 chars, symbol/digit/ambiguity options), memorable passphrases, PINs, strength meter, history |
| **Watchtower** | Security score; weak, reused, old and breached passwords (Have I Been Pwned, k-anonymity); sites that offer 2FA; http:// sites; expiring cards |
| **Vaults & Travel Mode** | Several vaults with icons/colors; Travel Mode hides every vault not marked "safe for travel" (1Password) |
| **Autofill extension** | Chrome/Edge/Brave/Firefox: an icon in login, 2FA, card and address fields; a fill menu; strong password suggestions on sign-up forms; "save this login?" after you sign in; Ctrl+Shift+L to fill; right-click → generate |
| **Desktop app** | Linux, Windows and macOS: a native window, a tray icon, start when you sign in, and a setup wizard and uninstaller like Jace Launcher's |
| **Extras** | Trash with restore, CSV import (Chrome, Firefox, Safari, 1Password, Bitwarden, Proton Pass, LastPass…), encrypted backup, auto-lock, clipboard auto-clear, Ctrl+K quick search, light/dark themes |

## Download

Get everything from the [latest release](https://github.com/okjace/jace-passwords/releases/latest).

| | |
|---|---|
| **Linux** | `JacePasswords-…-x86_64.AppImage`: make it executable and open it. Setup installs it for you |
| **Windows** | `JacePasswords-…-windows-x64.exe`: open it. Setup installs it, and no admin rights are needed |
| **macOS** | `JacePasswords-…-macos-arm64.app.zip` for Apple Silicon, or `-x86_64` for Intel: unzip and open it. Setup moves it to Applications |
| **Jace Browser / Firefox** | `jace-passwords-…-signed.xpi`: go to `about:addons`, click the gear icon, then **Install Add-on From File…** |
| **Chrome / Edge / Brave** | `jace-passwords-…-chrome.zip`: unzip it, then go to `chrome://extensions`, turn on Developer mode and click **Load unpacked** |

**On the web**, there's nothing to install: open https://jace-passwords.vercel.app and sign in with Jace. If you're already signed in to Jace, for example in Jace Browser, it signs you in automatically. Your vault is decrypted only inside your browser, with the same encryption as the desktop app, so both open the same synced vault. The server only handles Jace sign-in and passes the already-encrypted vault to Jace. For autofill and passkeys, use the desktop app with the extension.

The desktop app sets itself up the way Jace Launcher does. The first time you open the download, a setup wizard asks where to install it and adds shortcuts. Depending on the system, that's the applications menu, Start menu, Dock, desktop, terminal command, Windows "Installed apps" or app centers.

The setup can also start Jace Passwords in the tray when you sign in to your computer, so the browser extension can autofill without the window open. Closing the window leaves it in the tray, and the tray menu has **Lock** and **Quit**. Uninstall it from the app menu, from Windows Settings, or by running `jace-passwords --uninstall`. Your vault is kept unless you choose to delete it.

After installing the extension, open **Settings → Browser extension → Get pairing code** in the app and enter the code in the extension.

## Run from source

```bash
./run.sh
```

This needs Python 3.10+ and `cryptography`; `run.sh` installs it if it's missing. Without PySide6, the app opens in your browser at `http://127.0.0.1:47620`. With PySide6 installed (`pip install -r requirements-desktop.txt`), you get the desktop window, and `--browser` forces browser mode.

## Building

- **Linux AppImage:** `./packaging/build_appimage.sh`
- **Windows and macOS:** `python packaging/build.py`
- **Extension:** `python3 packaging/build_extension.py` builds `dist/jace-passwords-<version>-chrome.zip` and `dist/jace-passwords-<version>-firefox.xpi`.
- **Signing for Firefox and Jace Browser:** run `python3 packaging/sign_firefox.py`. It asks for your [addons.mozilla.org API keys](https://addons.mozilla.org/developers/addon/api/key/), uploads the add-on as unlisted (never published on the store), and saves `dist/jace-passwords-<version>-signed.xpi`. Bump `version` in `extension/manifest.json` first, because Mozilla won't sign the same version twice.

- **Web app:** `python3 packaging/deploy_vercel.py` deploys the static files in `jace_passwords/web` and the function in `webapp/api/jace.py` (Jace sign-in and the sync relay) to Vercel. It reads `VERCEL_TOKEN`, or asks for it. The site needs `JACE_WEB_CLIENT_ID`, `JACE_WEB_CLIENT_SECRET` and `SITE_URL` set on Vercel.

GitHub Actions (`.github/workflows/build.yml`) builds and tests all of these on every push, using each platform's installer self-test. To release:

1. Raise `APP_VERSION` in `jace_passwords/__init__.py` and `version` in `extension/manifest.json`.
2. Add a `## <version>` section to `CHANGELOG.md`.
3. Push to `main`.

Once every build passes, the workflow publishes a GitHub Release with all the downloads. If the repository secrets `AMO_JWT_ISSUER` and `AMO_JWT_SECRET` are set, it also signs the Firefox extension. If `VERCEL_TOKEN` is set, every push to `main` also redeploys the web app.

## Security

```
k1  = scrypt(master password, salt)        N=2^17, r=8, p=1
k2  = HKDF-SHA256(Secret Key)              128 random bits, only on your devices (vaults not linked to Jace)
KEK = k1 XOR k2   (or just k1 for a vault linked to Jace)
KEK unwraps a random 256-bit vault key, which encrypts the vault with AES-256-GCM
```

- **With a Jace account (the default when you're signed in):** you unlock with your master password alone. On a new device, you sign in with Jace and enter your master password. Like Bitwarden or Proton Pass, the vault stays end-to-end encrypted: your master password never leaves your device. Only your Jace sign-in can download the synced copy, and that copy is useless without your master password. You can still add a Secret Key under **Settings → Security**.
- **Without a Jace account:** like 1Password, a vault gets a Secret Key too, so a stolen vault file can't be brute-forced from your master password alone. The Secret Key is on the **Emergency Kit** shown when you create the vault.
- **Jace sync:** "Sign in with Jace" follows Jace's developer docs, like Jace Social. On Jace OS, the app gets its token from the computer's Jace account through token exchange (`jace-account --token-for`), with no prompt. The desktop app otherwise uses OAuth 2.0 + PKCE in your normal browser with a loopback redirect. The web app uses the code flow with its client secret on Vercel, plus silent `prompt=none` sign-in. The already-encrypted vault is stored in Jace's `pw-vault` sync collection. Jace never sees your master password or Secret Key, so it can't read or reset your vault. If two devices edit at the same time, each item keeps the newest change.
- **Local server:** listens on 127.0.0.1 only. Requests with a foreign `Host` are rejected (DNS-rebinding guard). The app window needs a session cookie that comes from a launch link only you can read. Every API call also needs a custom header. The extension needs a token it gets by pairing, and CORS is open only to extension origins.
- **Files:** they're in `~/.local/share/jace-passwords/` on Linux, `%APPDATA%\\Jace Passwords` on Windows, and `~/Library/Application Support/Jace Passwords` on macOS, with mode 0600. `vault.json` is encrypted. `device.json` holds this device's Secret Key, Jace token and paired extensions.

## Jace server setup (okjace/Jace)

Jace Passwords is Jace OAuth client `00000000-0000-0000-0000-000000000004`, which uses PKCE with the redirect `http://127.0.0.1:47620/jace/callback`.

- **Database:** the client's row is already in the live database (added 2026-11-12), so Sign in with Jace works.
- **Sync:** sync needs Jace deployed with the `pw-vault` collection, which is in `lib/constants.ts`, `lib/browserSync.ts` and `lib/schema.sql`. Until then, the app shows a "deploy Jace" message instead of syncing.

You can point the app at another server with `JACE_URL=…`, or at another data folder with `JACE_PASSWORDS_HOME=…`.

## Tests

```bash
python3 -m unittest discover tests
```

`tests/autofill-test.html` is a sample login, 2FA, checkout and sign-up page for trying the autofill script.

To try passkeys in a browser, run the command below and open `http://localhost:47699/tests/passkey-test.html`. It starts a fake site that checks registration and sign-in the way a real one does.

```bash
JACE_PASSWORDS_PORT=47621 JACE_PASSWORDS_HOME=/tmp/jp-e2e python3 tests/passkey_e2e.py
```

## License

MIT. See [LICENSE](LICENSE).
