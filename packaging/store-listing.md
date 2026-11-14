# Publishing Jace Passwords in the browser stores

Everything the Firefox add-ons store (addons.mozilla.org, "AMO") and the Chrome Web Store ask for,
ready to paste. Each release's files are on its GitHub release page:

| Store | Upload this file |
|---|---|
| Firefox add-ons | `jace-passwords-<version>-firefox-store.zip` (no `update_url`: the store updates it) |
| Chrome Web Store | `jace-passwords-<version>-chrome.zip` |

Privacy policy URL (both): **https://jace-passwords.vercel.app/privacy.html**
Homepage / support URL: **https://github.com/okjace/jace-passwords** (support: its Issues page)

## Listing text (both stores)

**Name:** Jace Passwords

**Summary** (Chrome ≤132 characters, Firefox ≤250):
> Your passwords, passkeys, 2FA codes, cards and addresses, end-to-end encrypted and filled in for you. Syncs with your Jace account.

**Category:** Firefox: *Privacy & Security*. Chrome: *Productivity* → *Tools*.

**Description:**
> Jace Passwords is a password manager tied to your Jace account.
>
> • Fills logins, passkeys, two-factor codes, credit and debit cards, and addresses, including card dropdowns and checkout frames.
> • Saves new logins, cards and addresses when you type them into a form (never your card's security code).
> • Passkeys: create and use passkeys on any site, stored in your vault and linked to their logins.
> • Built-in authenticator: 2FA codes fill themselves after your password.
> • Sign-in codes from email: when a site emails you a code, it's offered in the code field, read from your Gmail, Outlook or Proton Mail in this browser.
> • Password generator: random passwords, passphrases and PINs, with "only use" and "never use" characters for picky sites.
> • Watchtower: weak, reused and breached passwords, and sites where you could turn on 2FA or passkeys.
> • Works on its own, or connected to the Jace Passwords desktop app.
>
> Your vault is encrypted with AES-256-GCM on your device. With a master password, only you can open it: nobody else, including us, can read it. No ads, no analytics, no tracking. Open source: github.com/okjace/jace-passwords

**Screenshots** (Chrome: 1280×800 or 640×400, at least 1; Firefox: optional, recommended): take them yourself in the browser:
1. The fill list on a sign-in page. 2. The 2FA menu with a code. 3. The popup on "This site". 4. The generator. 5. The full app (Watchtower).

**Icon:** `extension/icons/icon128.png` (Chrome also wants a 440×280 small promo tile: optional).

## Why each permission (both stores ask)

| Permission | Why |
|---|---|
| Content scripts on all websites (`http://*/*`, `https://*/*`) | A password manager has to work on every site: it finds sign-in, 2FA, card and address fields to fill when the user picks an item, offers to save what the user types into sign-in and checkout forms, answers websites' passkey (WebAuthn) requests, and reads sign-in codes from the user's open inbox tab. |
| `storage` | Keeps the encrypted vault, settings and the user's Jace sign-in on the device. |
| `identity` | Opens the "Sign in with Jace" window (OAuth). |
| `contextMenus` | Right-click "Generate password" and "Fill" menu items. |
| `activeTab` | Fills the tab the user is on when they use the popup or keyboard shortcut. |
| Host `http://127.0.0.1:47620/*` | Talks to the Jace Passwords desktop app on the same computer, if the user connects the extension to it. |
| Host `https://jace-passwords.vercel.app/*` | The extension's own service: Jace sign-in, encrypted vault sync, and the vault key for vaults that unlock with a Jace account. |
| Optional host `https://mail.google.com/*` | Only if the user turns on Gmail for email codes: reads Gmail's unread-mail feed to find a sign-in code. |

**Single purpose (Chrome):** Jace Passwords is a password manager: it stores the user's passwords, passkeys, 2FA codes, cards and addresses and fills them into websites.

**Remote code (Chrome):** No, I am not using remote code. All JavaScript is in the package.

## Data use answers

**Chrome Web Store, "Privacy practices" tab.** Tick what the extension handles:
- *Personally identifiable information* (names, addresses, email, phone saved in the vault)
- *Authentication information* (passwords, passkeys, 2FA secrets)
- *Financial and payment information* (saved cards)
- *Personal communications* (sign-in codes read from the user's inbox, in the browser only, never sent anywhere)
- *Website content* (form fields read to fill and save)

Then tick all three certifications: not sold to third parties; not used for unrelated purposes; not used for creditworthiness or lending.

**Firefox.** The manifest already declares it (`data_collection_permissions`): *authentication info*, *personally identifying info*, *financial and payment info*. These go, encrypted, to the user's own Jace account for sync. Email codes and website content never leave the browser, so they aren't declared.

**Notes for reviewers** (paste into "Notes to reviewer" / "Test instructions"):
> Jace Passwords works on its own: click the toolbar button → Sign in with Jace (free account at https://jaceo.vercel.app). Create a vault at https://jace-passwords.vercel.app/app, then the extension fills its logins on any sign-in page. The vault is encrypted on the device (AES-256-GCM; key from scrypt of the master password). Source code is not minified or bundled: every file in the package is the readable source from https://github.com/okjace/jace-passwords (extension/ plus jace_passwords/web/webvault.js and words.js, copied into vault/).

## Step by step

### Firefox add-ons store (free)
The add-on already exists on addons.mozilla.org as an *unlisted* add-on: every release signs its GitHub
download there, as version X. The store copy of the same release is version **X.1** (Mozilla allows each
number once), built without `update_url` so the store updates it. GitHub copies keep updating from GitHub.

1. Sign in at https://addons.mozilla.org/developers/ with the account that has the API keys.
2. *My Add-ons* → **Jace Passwords** → **Upload New Version** → **On this site** (listed) → upload
   `jace-passwords-<version>.1-firefox-store.zip` from the newest release.
3. Fill in the listing from above (name, summary, description, category, support site, privacy policy,
   license MIT, notes for reviewers) and submit.
4. Then turn on automatic store uploads, so every release is also sent to the store:
   `gh variable set AMO_LISTED -R okjace/jace-passwords -b 1`

### Chrome Web Store ($5, one time)
1. Register at https://chrome.google.com/webstore/devconsole (Google account, $5 fee, verify your email).
2. **New item** → upload `jace-passwords-<version>-chrome.zip` from the newest release.
3. *Store listing*: name, summary, description, category, icon, screenshots (above).
4. *Privacy practices*: single purpose, permission reasons, remote code: No, data use (above), privacy policy URL.
5. *Distribution*: Public (or Unlisted), all regions. **Submit for review** (usually a few days for an extension with access to all websites).
6. Later versions: upload the new `-chrome.zip` on the item's *Package* tab and submit. Copies installed from the store update themselves; the "update available" bar only shows in copies loaded by hand.
