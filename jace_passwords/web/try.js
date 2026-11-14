"use strict";
/* Practice page (try.html, try-card.html): shows what got filled, pretends to submit forms (nothing is
   sent anywhere), and tries passkeys on this page. */
(() => {
  const mark = (el) => el.classList.toggle("filled", !!(el.type === "radio" ? el.checked : el.value));
  const fields = () => [...document.querySelectorAll("input, select")];
  function refresh() {
    fields().forEach(mark);
    document.querySelectorAll("section").forEach((s) => {
      const badge = s.querySelector("[data-badge]");
      if (!badge || s.id === "passkey") return;
      const all = [...s.querySelectorAll("input:not([type=radio]), select")];
      const n = all.filter((x) => x.value).length;
      badge.textContent = n ? `${n} of ${all.length} filled` : "not filled";
      badge.classList.toggle("ok", n > 0);
    });
  }
  ["input", "change"].forEach((t) => document.addEventListener(t, refresh, true));
  setInterval(refresh, 700); // fills that set values without events still show

  // "Submitting": show what would have been sent, then change the address so the extension offers to save.
  document.querySelectorAll("form[data-try]").forEach((f) => f.addEventListener("submit", (e) => {
    e.preventDefault();
    const sent = [...f.querySelectorAll("input, select")].filter((x) => x.value && (x.type !== "radio" || x.checked))
      .map((x) => `${x.labels?.[0]?.textContent?.trim() || x.name}: ${/password|cvc|csc|cvv/i.test(x.name + x.autocomplete) ? "•".repeat(Math.min(x.value.length, 12)) : x.value}`);
    const out = f.querySelector(".result");
    if (out) out.textContent = sent.length ? `Would have sent (but didn't): ${sent.join(" · ")}` : "Nothing filled yet.";
    if (sent.length) setTimeout(() => history.pushState(null, "", `${location.pathname}?sent=${f.dataset.try}#${f.closest("section")?.id || ""}`), 400);
  }));

  // Passkeys for this page only (relying party = this site). Nothing is verified by a server: it shows what
  // the browser and Jace Passwords returned.
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const result = document.getElementById("pk-result");
  const say = (t, ok) => { if (result) { result.textContent = t; result.style.color = ok ? "var(--ok)" : ""; } };
  const badge = document.querySelector("#passkey [data-badge]");
  const done = (t) => { if (badge) { badge.textContent = t; badge.classList.add("ok"); } };
  document.getElementById("pk-create")?.addEventListener("click", async () => {
    const name = document.getElementById("pk-name").value.trim() || "you@example.com";
    try {
      const cred = await navigator.credentials.create({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { id: location.hostname, name: "Jace Passwords practice page" },
        user: { id: new TextEncoder().encode("try:" + name), name, displayName: name },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
        timeout: 120000 } });
      say(`✓ Passkey created for ${name} (id ${b64u(cred.rawId).slice(0, 12)}…). Now try "Sign in with a passkey".`, true);
      done("created");
    } catch (e) { say(`Not created: ${e.message || e.name}`); }
  });
  document.getElementById("pk-get")?.addEventListener("click", async () => {
    try {
      const cred = await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: location.hostname, userVerification: "preferred", timeout: 120000 } });
      const user = cred.response.userHandle ? new TextDecoder().decode(cred.response.userHandle).replace(/^try:/, "") : "?";
      say(`✓ Signed in with the passkey for ${user}: the signature came back from your passkey (id ${b64u(cred.rawId).slice(0, 12)}…).`, true);
      done("signed in");
    } catch (e) { say(`Not signed in: ${e.message || e.name}`); }
  });
  refresh();
})();
