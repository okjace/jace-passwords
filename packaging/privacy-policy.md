# Jace Passwords privacy policy

For the Jace Passwords desktop app, web app (jace-passwords.vercel.app) and browser extension. Last updated November 14, 2026.

## The short version

Your vault (logins, passwords, passkeys, two-factor secrets, cards, addresses, notes) is encrypted on your own device before it's saved or synced. Jace Passwords has no ads, no analytics and no tracking, and never sells or shares your data.

## What's stored, and where

- **Your vault** is encrypted with AES-256-GCM on your device. With a master password it's end-to-end encrypted: the key comes from your master password (and Secret Key, if you use one) and never leaves your devices, so nobody else, including us, can read it.

- **If you unlock with your Jace account instead of a master password,** the Jace Passwords server derives a key for your account when you sign in. Your vault is still encrypted, but not end-to-end. The app tells you this before you choose it.

- **If you open the vault without a password, or have a device remember your master password,** the key is kept on that device only, encrypted with a key that also stays on that device.

- **Sync:** when you sign in with Jace, the encrypted vault is stored in your Jace account's sync storage so your other devices can get it.

- **In the browser extension:** your encrypted vault, settings and Jace sign-in are kept in the browser's extension storage, and the unlocked key in memory-only session storage that's cleared when you lock or close the browser.

## What leaves your device

- **Jace (jaceo.vercel.app)**: Your Jace sign-in, and your encrypted vault (Signing in and sync)

- **Jace Passwords (jace-passwords.vercel.app)**: Your Jace sign-in token; your encrypted vault passing through (Signing in from the web app and extension, sync, and the key for vaults that unlock with Jace)

- **Have I Been Pwned (api.pwnedpasswords.com)**: The first 5 characters of a password's SHA-1 hash, never the password, only when you check for breaches (Finding leaked passwords)

- **2fa.directory, passkeys.directory, Have I Been Pwned's breach list**: Nothing about you: the same public lists are downloaded for everyone (Watchtower's 2FA, passkey and breached-site checks)

- **GitHub**: Nothing about you (Checking for app updates)

## Sign-in codes from your email

When a website emails you a sign-in code, the extension can offer it in that site's code field. It reads the code from your Gmail, Outlook or Proton Mail inbox **in your own browser**: from an inbox you have open in a tab; from Gmail's unread-mail feed, if you turn Gmail on; or by opening your inbox in a background tab for a few seconds, if you turn Outlook or Proton Mail on. This happens only when you open the code field's menu, and only for the email services you turned on. It uses your existing sign-in to those services and never asks for your email password. Nothing it reads is stored or sent anywhere: the code goes only into the field you click.

## Field reports

If you tell the extension what a form field is ("this is the password field", "nothing to fill here"), it remembers that on your device. If you're signed in with Jace, the report is also sent to Jace so autofill recognizes the field for everyone: the website's host name, the field's name on the page, the kind you picked, and your Jace account id (used to keep one report per person and limit how many each account can send). What you typed into the field is never sent. A report applies for everyone once two people agree on it (reports from the project's owner apply right away). Everyone's reports are published as one list, without account ids, which every copy of the extension downloads; it doesn't look up the sites you visit. Reports from other people can't turn a field into a password or card-security field unless it already looks like one.

## The browser extension's permissions

- **Read and change data on websites:** to find login, two-factor, card and address fields and fill them when you choose, to offer to save what you type into sign-in and checkout forms, to answer websites' passkey requests, and to read sign-in codes from your inbox tab. Nothing is filled without your action, and card details only go to the page's own site or its payment provider's frames.

- **mail.google.com (optional, asked for when you turn Gmail on):** reading Gmail's unread-mail feed for sign-in codes.

- **storage:** keeping your encrypted vault, settings and sign-in on your device.

- **identity:** opening the "Sign in with Jace" window.

- **contextMenus, activeTab:** the right-click "generate password", "fill" and "what is this field?" menu items, and seeing which site the tab you're on is when you open the toolbar button.

- **127.0.0.1:47620 and jace-passwords.vercel.app:** talking to the Jace Passwords desktop app on your computer, if you connect to it, and to the Jace Passwords site for sign-in and sync.

## Your choices

You can export your vault, delete items, turn email codes off, sign out of Jace (sync stops), or delete the vault from a device. Uninstalling the app or extension removes its local data. Deleting your Jace sync data removes the synced copy.

## Open source and contact

All of Jace Passwords' code is public at github.com/okjace/jace-passwords (https://github.com/okjace/jace-passwords). Questions or requests: open an issue (https://github.com/okjace/jace-passwords/issues).

Full policy: https://jace-passwords.vercel.app/privacy
