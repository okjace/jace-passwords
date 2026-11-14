/* Jace Passwords — finding sign-in codes in email text (subjects, previews, message bodies).
 * Shared by content.js (reading an inbox tab) and background.js (reading Gmail's unread-mail feed). */
(() => {
  if (globalThis.JPMail) return;
  // 4–8 characters; not a year, not 0000 / 1111.
  const okCode = (c) => c.length >= 4 && c.length <= 8 && !/^(19|20)\d\d$/.test(c) && !/^(\d)\1+$/.test(c);
  // Words that mean "a code", not just "sign in" (so "Sign in to see 1000 deals" isn't a code).
  const KEYWORDS = /(code|passcode|\bpin\b|\botp\b|one[- ]time|verif|\b2fa\b|authenticat|c[oó]digo|\bkod|验证码)/gi;
  const SHOPPING = /promo|coupon|discount|gift|voucher|referral|% off/i;
  // 482913, 482 913, G-482913, or letters-and-digits like XK7P2Q.
  const CANDIDATE = /(?:^|[^A-Za-z0-9-])(G-\d{6}|\d{3}[ -]\d{3}|\d{4,8}|(?=[A-Z0-9]{5,8}(?![A-Za-z0-9]))(?=[A-Z0-9]*\d)[A-Z0-9]*[A-Z][A-Z0-9]*)(?![A-Za-z0-9])/g;

  function codesIn(text) {
    const t = String(text || "").replace(/\s+/g, " ");
    const found = [];
    const kw = new RegExp(KEYWORDS.source, "gi");
    let m;
    while ((m = kw.exec(t)) && found.length < 3) {
      const win = t.slice(Math.max(0, m.index - 40), m.index + m[0].length + 70);
      if (SHOPPING.test(win)) continue; // shopping codes, not sign-in codes
      const cand = new RegExp(CANDIDATE.source, "g");
      let c;
      while ((c = cand.exec(win))) {
        const code = c[1].replace(/^G-/, "").replace(/[ -]/g, "");
        if (okCode(code) && !found.includes(code)) found.push(code);
      }
    }
    return found;
  }

  // The site's name as it appears in emails: "github" for github.com, "bbc" for bbc.co.uk.
  function siteName(host) {
    const parts = String(host || "").replace(/^www\./, "").split(".");
    return (parts.length > 2 && parts.at(-2).length <= 3 ? parts.at(-3) : parts.at(-2)) || "";
  }

  globalThis.JPMail = { codesIn, okCode, siteName };
})();
