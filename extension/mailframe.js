/* Jace Passwords — inside a webmail's message frame (Proton Mail shows each message in a frame the page around
 * it can't always read). Finds sign-in codes in the message here, and tells the inbox page's content.js: only
 * the codes and how much text there was, never the message itself. */
(() => {
  if (window === window.top || globalThis.__jpMailFrame) return;
  globalThis.__jpMailFrame = true;
  const report = () => {
    const text = (document.body?.innerText || document.body?.textContent || "").trim();
    try { window.top.postMessage({ tag: "jace-passwords-mailframe", chars: text.length, codes: globalThis.JPMail.codesIn(text) }, "*"); } catch { /* */ }
  };
  report();
  new MutationObserver(report).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  addEventListener("load", report);
})();
