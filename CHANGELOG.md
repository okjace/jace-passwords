# Changelog

## 1.6.6

- **Signing in asks first:** pressing Sign in with Jace (web app, extension, and the desktop app outside Jace OS) now always shows Jace's "Allow Jace Passwords to use your account?" page, even in Jace Browser, which used to approve it by itself.
- **Practice page:** jace-passwords.vercel.app/try has a form for every kind of autofill, and the front page links to it.

## 1.6.5

- **Desktop app on Jace OS: signs in only with the computer's Jace account.** The button says "Use this computer's Jace account", and it never opens the browser. If the computer isn't signed in to Jace, it tells you to sign in in Jace OS first. On Windows, macOS and other Linux, sign-in works as before.

## 1.6.4

- **Switching Jace accounts works:** in the extension and the web app, signing in with a different Jace account now opens that account's vault instead of the last one's. Each account's vault is kept separately on the device (still encrypted, with its own settings such as a remembered master password) and comes back when that account signs in again.

## 1.6.3

- **Field reports need two people to agree** before they apply for everyone (okjace's apply right away). Your own report still applies for you immediately, and the extension now tells you whether it applies for everyone yet.

## 1.6.2

- **Safer field reports:** other people's reports can't turn a field into a password field unless it's really a password box, or into a card-number or security-code field unless it looks like one. So one wrong or hostile report can't make autofill put passwords into a public text box. Your own reports still apply exactly as you set them.
- The privacy policy now explains field reports, including that Jace stores them with your account id.

## 1.6.1

- The extension no longer asks for the `scripting` permission, which it didn't use.
- The website's front page is now an introduction; the web app is at jace-passwords.vercel.app/app.

## 1.6.0

- **Report a field:** if autofill gets a field wrong (or misses it), pick **Wrong kind of field? Report it** at the bottom of the fill list, or right-click the field → **What is this field?**, and choose what it is: email or username, password, 2FA code, name, address, card number, "nothing to fill here" and more. It applies for you right away and, signed in with Jace, for everyone. Reports are kept by Jace and only name the site and the field, never what's typed in it. The extension downloads everyone's reports as one list, so it never tells anyone which sites you visit.
- **"No passkeys found":** when a site asks for a passkey and your vault has none for it, Jace Passwords now says so, with **Use another device** to try a phone or security key instead.

## 1.5.0

- **Email codes without an open inbox tab:** in the extension's popup, **✉ Email codes**, turn on Gmail, Outlook or Proton Mail. Gmail is read from its unread-mail feed (the browser asks you to allow mail.google.com once); Outlook and Proton Mail open your inbox in a background tab for a few seconds, then close it. Uses your existing sign-in in this browser, only when you open a code field's menu. The 2FA menu shows right away and the emailed code drops in when it's found.
- **Ready for the browser stores:** each release now has a `-firefox-store.zip` for the Firefox add-ons store, a privacy policy at jace-passwords.vercel.app/privacy.html, and `packaging/store-listing.md` with the listing text, permission reasons and step-by-step instructions for Firefox and Chrome. The extension declares its data use for Firefox, and copies installed from the Chrome Web Store don't show the "update available" bar.

## 1.4.0

- **Codes from your email:** when a site emails you a sign-in code, the extension's 2FA menu offers it, read from your Gmail, Outlook or Proton Mail tab in the same browser. Keep your inbox open in a tab. It's read only when you open that menu, and nothing is sent anywhere.
- **Password generator:** **Only use these characters** (for sites that allow just a few) and **Never use these characters** (for sites that reject some symbols).
- **The fill list no longer gets cut off:** it fits in the space you have, scrolls when needed, and page styles can't push it off the screen.

## 1.3.5

- **Remember your master password in the extension:** when you unlock in the extension's popup, tick **Remember my password on this browser**. After that it opens by itself; **Forget password** at the bottom of the popup turns it off.

## 1.3.4

- **Remember my master password on this device:** Settings → Security. Your vault keeps its master password and stays encrypted, but this device opens it by itself and doesn't auto-lock. Other devices, and restoring from Jace, still need the password. Turn it off any time.
- The extension popup shows an **Open** button instead of a password box when the vault doesn't need one here.

## 1.3.3

- **Adding or changing a master password works in Firefox and Jace Browser.** They refused a step of the password key calculation with "The operation failed for an operation-specific reason". It's now done in a way every browser accepts, with exactly the same result, so existing vaults open as before.

## 1.3.2

- **Deleting a vault works:** the "Are you sure?" question is now the app's own box. Some app windows quietly answered "no" to the browser's, so nothing happened. The same goes for deleting items, passkeys and Trash.
- **Deleted vaults stay deleted:** sync no longer brings them back from another device.
- **New passkeys join your existing login** for that site, even when the site's username doesn't match exactly. They show on the login, in its edit form and in the Passkeys tab, which now lists each login's passkeys.
- **Signing in with the computer's Jace account (Jace OS) is only in the desktop app.** The web app no longer signs in silently; press "Sign in with Jace".
- **Clearer errors:** if your browser's encryption fails, the message now says what Jace Passwords was doing.

## 1.3.1

- **The desktop app updates itself:** it checks GitHub for new releases, downloads the right file in the background, checks it against GitHub's SHA-256, and installs it when you quit or when you choose **Restart to update** in the tray. It installs in the same place, with the same shortcuts and settings. Install 1.3.1 by hand once, and it handles every update after that.
- **The extension updates itself in Jace Browser and Firefox,** from this release's signed copy on. Install `jace-passwords-1.3.1-signed.xpi` once, and new versions arrive automatically.
- **Chrome, Edge and Brave:** a copy loaded with "Load unpacked" can't update itself, so its popup now says when a new version is out.
- **Every release now signs the Firefox extension automatically.**

## 1.3.0

- **Card autofill works on many more checkouts:**
  - Fields marked `billing`, `shipping` or with a section prefix are recognized, and so are fields found only by their label.
  - **Dropdowns:** the expiry month (as "09", "9", "September" or "Sep"), the expiry year (2029 or 29) and the card type.
  - **Brand and credit/debit buttons**, and first and last name on the card.
  - **Expiry text fields** follow the field's own format, like "MM/YY", "MM / YY" or "MM/YYYY".
  - **Card fields in their own frames,** as on Stripe and other payment providers, now fill too. Only frames from the same website or a known payment provider receive your card details, never ads or other third parties.
- **Address and contact autofill:** name (full, or first, middle and last), email, phone, address lines, city, state, ZIP, country, company and birthday. Country dropdowns work with names or ISO codes, and US state dropdowns with names or abbreviations.
- **Save what you type:** after you submit a checkout or address form, Jace Passwords offers to save the card and the address. It never saves the CVC, never offers details you already have, and offers changed details as an update.

## 1.2.0

- **Import from other password managers, passkeys included:**
  - **Bitwarden** (.json): logins, passkeys, 2FA codes, cards, notes and identities.
  - **Credential Exchange / CXF** (.json): logins, passkeys, 2FA codes, cards and notes.
  - **1Password** (.1pux) and **Proton Pass** (zip): logins, 2FA codes, cards, notes and identities. Neither app exports usable passkeys.
  - **CSV** from Chrome, Firefox, Safari, Edge and others, as before.
  - Imported passkeys keep their original IDs and keys, so websites still recognize them.
- **Passkeys linked to logins:** an imported passkey joins the login you already have for that site and account, adding to it instead of duplicating it. Every passkey has **🔗 Link to another login**, to move it, with its key, onto the right login.
- **Open without a password:** skip the master password when creating a vault, with or without a Jace account. Without Jace, the vault opens on that device by itself; it's still encrypted on disk, but anyone using the device can open it. With Jace, it opens whenever you're signed in. Add a master password any time in Settings.
- **Any master password length.** The strength meter still warns about weak ones.
- **Watchtower uses established sources:**
  - **2fa.directory** for which of your sites offer 2FA, by which methods, with setup guides.
  - **The passkeys directory** for sites where you could use a passkey.
  - **Have I Been Pwned's breach list** for **compromised websites**: sites breached after you last set your password there.
  - The score now counts vulnerabilities fully and recommendations less.
- **2FA autofill works on more sites:**
  - Fields named just "code", "token" or "pin" are now recognized.
  - Codes split across one-digit boxes are filled one digit per box.
  - The menu opens by itself on a 2FA field.
  - **Fill 2FA code** no longer forgets which login you just used.

## 1.1.0

- **The browser extension works on its own,** with no desktop app needed:
  - Click the toolbar button, then **Sign in with Jace**. It opens your vault from your Jace account and unlocks it with your master password, or with **Unlock with Jace** if you skipped the password.
  - Autofill, saving logins, 2FA codes and passkeys all work, and every change syncs through Jace. Passkeys made in the extension also work in the desktop app, and the other way round.
  - While unlocked, the key is kept only in the browser's memory until you lock or close the browser.
- **Still works with the desktop app:** if the extension is paired with the desktop app, it uses the app as before. **Disconnect** switches it to standalone, and **Connect to the desktop app** switches it back.
- **One vault engine:** the web app and the extension share it, and it uses exactly the desktop app's vault format.

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
