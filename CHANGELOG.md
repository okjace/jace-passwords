# Changelog

## 1.0.1

- **Fixed:** Sign in with Jace said "Couldn't reach Jace" in the Linux desktop app on Jace OS, Arch, Fedora and other non-Ubuntu systems. The packaged app looked for trusted certificates where Ubuntu keeps them, so every HTTPS request failed. It now uses your system's certificates, with a bundled set as a fallback.
- **Fixed:** the desktop app opened in light mode on a dark desktop. It now follows your system's light or dark setting, and switches live when you change it.
- **Clearer errors:** a certificate problem now says so, instead of blaming your internet connection.
- **The browser extension is unchanged.** Keep using `jace-passwords-1.0.0-signed.xpi`, which is also attached to this release.

## 1.0.0

The first release of Jace Passwords.

- **Vault:** logins, credit and debit cards, secure notes, identities and email aliases. It's end-to-end encrypted with AES-256-GCM, using your master password plus a Secret Key (scrypt + HKDF).
- **Sign in with Jace:** your encrypted vault syncs to your Jace account, and Jace only ever stores ciphertext. Signing in works like Jace Social: on Jace OS, the app uses the computer's Jace account without asking. The desktop app signs in through your normal browser, and the web app signs you in automatically when you're already signed in to Jace.
- **Web app** at https://jace-passwords.vercel.app: the same vault, decrypted only in your browser.
- **Passkeys:** create passkeys and sign in with them on any site. You can also pick one from the username field's menu.
- **Two-factor codes:** stored right on the login, with a live countdown and autofill.
- **"Sign in with…":** a login can record that a site uses Google, Apple, Microsoft, GitHub, Facebook, X, Discord or Jace.
- **Password generator:** random passwords, passphrases and PINs.
- **Watchtower:** finds weak, reused, old and breached passwords, sites that offer 2FA, and expiring cards.
- **More vault features:** multiple vaults, Travel Mode, trash, CSV import, encrypted backups, auto-lock and clipboard clearing.
- **Desktop app for Linux, Windows and macOS:**
  - a setup wizard like Jace Launcher's
  - a tray icon, so autofill keeps working with the window closed
  - an option to start when you sign in to your computer
- **Browser extension for Jace Browser, Firefox, Chrome, Edge and Brave:**
  - autofill for logins, 2FA codes, cards and addresses
  - offers to save logins after you sign in
  - suggests strong passwords on sign-up forms
  - handles passkeys
