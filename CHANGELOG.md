# Changelog

## 1.0.3

- **Skip the master password:** when you're signed in with Jace, you can choose **Skip: unlock with my Jace account** instead of making a master password. Your vault then unlocks whenever you're signed in to Jace, with **Unlock with Jace** on the lock screen, and on the web and new devices too.
  - ⚠ This mode is encrypted, but **not end-to-end**: the Jace Passwords server keeps the key for your account, so whoever controls it, or gets into your Jace account, could open the vault.
  - You can switch any time in **Settings → Security**: **Add a master password** makes it end-to-end encrypted, and **Unlock with Jace instead** goes the other way.
- **Browser extension:** for a vault that unlocks with Jace, just press Unlock and leave the password empty.

## 1.0.2

- **No Secret Key with a Jace account:** a vault created while you're signed in with Jace no longer gets a Secret Key. On a new device, or on the web, you sign in with Jace and enter your master password. Your vault stays end-to-end encrypted: your master password never leaves your device, and only your Jace sign-in can download the synced copy.
- **Existing vaults:** a vault that already has a Secret Key can drop it under **Settings → Security → Stop using a Secret Key**. You can add one back at any time.
- **Unlinked vaults** (used without a Jace account) still get a Secret Key, as before.

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
