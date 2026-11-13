/* Jace Passwords — in-page autofill: field icons, fill menu, save prompt. */
(() => {
  if (window.__jacePasswords) return;
  window.__jacePasswords = true;
  const B = globalThis.browser ?? globalThis.chrome;
  const send = (msg) => new Promise((res) => { try { B.runtime.sendMessage(msg, (r) => res(r || {})); } catch { res({}); } });
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const ICON = `<svg viewBox="0 0 32 32" width="16" height="16"><rect width="32" height="32" rx="9" fill="#3ddc84"/><path d="M11.5 14v-2.5a4.5 4.5 0 0 1 9 0V14" fill="none" stroke="#0c1410" stroke-width="2.6" stroke-linecap="round"/><rect x="9" y="14" width="14" height="11" rx="3" fill="#0c1410"/><circle cx="16" cy="19" r="1.7" fill="#3ddc84"/></svg>`;

  /* ---------- field detection ---------- */
  const visible = (el) => { const r = el.getBoundingClientRect(); return r.width > 20 && r.height > 10 && getComputedStyle(el).visibility !== "hidden"; };
  const hint = (el) => [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.getAttribute("autocomplete"), el.labels?.[0]?.textContent].join(" ").toLowerCase();

  function classify(el) {
    if (!(el instanceof HTMLInputElement) || el.disabled || el.readOnly) return null;
    const type = (el.type || "text").toLowerCase();
    if (!["text", "email", "password", "tel", "number", "search", ""].includes(type)) return null;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    const h = hint(el);
    if (ac.includes("one-time-code") || /\b(otp|totp|2fa|mfa|one.?time|verification.?code|authenticator|security.?code)\b/.test(h) && !/cvv|cvc|csc/.test(h)) return "totp";
    if (ac.startsWith("cc-") || /card.?number|cardnum|cc-?num|ccnumber/.test(h)) {
      if (ac === "cc-number" || /card.?number|cardnum|cc-?num|ccnumber/.test(h)) return "cc-number";
      if (ac === "cc-name") return "cc-name";
      if (ac === "cc-exp") return "cc-exp";
      if (ac === "cc-exp-month") return "cc-exp-month";
      if (ac === "cc-exp-year") return "cc-exp-year";
      if (ac === "cc-csc") return "cc-csc";
    }
    if (/\b(cvv|cvc|csc|card.?code|security.?code)\b/.test(h)) return "cc-csc";
    if (/name.?on.?card|card.?holder|cardholder/.test(h)) return "cc-name";
    if (/\b(exp(iry|iration)?.?(date)?)\b|mm.?\/.?yy/.test(h) && !/month|year/.test(h)) return "cc-exp";
    if (/exp.*month|cc-?month/.test(h)) return "cc-exp-month";
    if (/exp.*year|cc-?year/.test(h)) return "cc-exp-year";
    if (type === "password") {
      if (ac === "new-password" || /new|confirm|create|repeat|retype|signup|register/.test(h)) return "new-password";
      return "password";
    }
    const acTokens = ac.split(/\s+/);
    if (acTokens.includes("webauthn") && type !== "password") return "username"; // passkey autofill field
    if (acTokens.includes("username") || ac === "email" || type === "email" || /user|login|email|e-mail|account|identifier/.test(h)) {
      // a login username only if there's a password field nearby (or it's a username-first page)
      const scope = el.form || document;
      if (scope.querySelector("input[type=password]") || acTokens.includes("username") || /login|signin|sign.?in|identifier/.test(h + location.pathname)) return "username";
      if (ac === "email" || type === "email") return "id-email";
    }
    const idMap = { "given-name": "id-first", "family-name": "id-last", name: "id-name", tel: "id-phone", "street-address": "id-address1", "address-line1": "id-address1",
      "address-line2": "id-address2", "address-level2": "id-city", "address-level1": "id-state", "postal-code": "id-zip", country: "id-country", "country-name": "id-country", organization: "id-company", bday: "id-birthday" };
    if (idMap[ac]) return idMap[ac];
    return null;
  }

  const KIND_GROUP = (k) => k === "username" || k === "password" ? "login" : k === "new-password" ? "new" : k === "totp" ? "totp" : k.startsWith("cc-") ? "card" : k.startsWith("id-") ? "identity" : null;

  /* ---------- filling ---------- */
  function setValue(el, value) {
    if (value == null || value === "") return;
    el.focus();
    const proto = Object.getPrototypeOf(el);
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.style.transition = "background-color .4s";
    const bg = el.style.backgroundColor;
    el.style.backgroundColor = "rgba(31,157,90,.12)";
    setTimeout(() => (el.style.backgroundColor = bg), 600);
  }

  function fieldsIn(scope) {
    return [...scope.querySelectorAll("input")].filter((el) => visible(el)).map((el) => ({ el, kind: classify(el) })).filter((x) => x.kind);
  }

  function fill(data, anchor) {
    const scope = anchor?.form || anchor?.closest("form") || document;
    let fields = fieldsIn(scope);
    if (!fields.length && scope !== document) fields = fieldsIn(document);
    let did = false;
    for (const { el, kind } of fields) {
      let v = null;
      if (data.type === "login") {
        if (kind === "username") v = data.username;
        else if (kind === "password") v = data.password;
        else if (kind === "totp" && data.totp && !fields.some((f) => f.kind === "password")) v = data.totp;
      } else if (data.type === "card") {
        const y = String(data.expYear || ""), m = String(data.expMonth || "").padStart(2, "0");
        v = { "cc-number": data.number, "cc-name": data.cardholder, "cc-csc": data.cvv, "cc-exp-month": m,
          "cc-exp-year": (el.maxLength === 2 ? y.slice(-2) : y), "cc-exp": m && y ? `${m}/${y.slice(-2)}` : "" }[kind];
      } else if (data.type === "identity") {
        const [first, ...rest] = (data.fullName || "").split(" ");
        v = { "id-first": data.firstName || first, "id-last": data.lastName || rest.join(" "), "id-name": data.fullName, "id-email": data.email, "id-phone": data.phone,
          "id-address1": data.address1, "id-address2": data.address2, "id-city": data.city, "id-state": data.state, "id-zip": data.zip,
          "id-country": data.country, "id-company": data.company, "id-birthday": data.birthday, "username": data.email }[kind];
      } else if (data.type === "totp") {
        if (kind === "totp") v = data.code;
      }
      if (v) { setValue(el, v); did = true; }
    }
    // selects for card expiry
    if (data.type === "card") {
      for (const sel of scope.querySelectorAll("select")) {
        const h = hint(sel);
        const want = /month|mm/.test(h) ? String(+data.expMonth) : /year|yy/.test(h) ? String(data.expYear) : null;
        if (!want) continue;
        const opt = [...sel.options].find((o) => o.value === want || +o.value === +want || o.value.endsWith(want.slice(-2)) || o.text.trim() === want);
        if (opt) { sel.value = opt.value; sel.dispatchEvent(new Event("change", { bubbles: true })); did = true; }
      }
    }
    return did;
  }

  /* ---------- UI (shadow DOM so pages can't restyle or read it easily) ---------- */
  const host = document.createElement("jace-passwords");
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `<style>
    :host { all: initial; }
    .icon { position: fixed; z-index: 2147483646; width: 22px; height: 22px; border: 0; padding: 3px; border-radius: 6px; background: transparent; cursor: pointer; display: none; }
    .icon:hover { background: rgba(109,93,252,.12); }
    .menu { position: fixed; z-index: 2147483647; width: 300px; max-height: 340px; overflow: auto; background: #fff; color: #16181d; border: 1px solid #dfe2e7;
      border-radius: 14px; box-shadow: 0 12px 40px rgba(20,20,50,.22); font: 13px/1.4 system-ui, sans-serif; display: none; padding: 6px; }
    @media (prefers-color-scheme: dark) { .menu { background: #1c1f26; color: #e6e8eb; border-color: #2a2f38; } .it:hover, .it:focus { background: rgba(61,220,132,.14) !important; } .muted { color: #8b919c !important; } }
    .hd { display: flex; align-items: center; gap: 8px; padding: 6px 8px 8px; font-weight: 700; font-size: 12px; }
    .it { display: flex; align-items: center; gap: 10px; padding: 8px; border-radius: 10px; cursor: pointer; border: 0; background: none; width: 100%; text-align: left; color: inherit; font: inherit; }
    .it:hover, .it:focus { background: rgba(31,157,90,.12); outline: none; }
    .tile { width: 28px; height: 28px; border-radius: 8px; color: #fff; display: grid; place-items: center; font-weight: 800; flex: none; }
    .t { font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .muted { color: #5d6470; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .m { min-width: 0; flex: 1; }
    .pw { font-family: ui-monospace, monospace; font-size: 12px; word-break: break-all; }
    .msg { padding: 10px; color: #5d6470; }
    input { width: 100%; box-sizing: border-box; padding: 8px 10px; border-radius: 8px; border: 1px solid #c9c9d9; font: inherit; margin: 4px 0; background: inherit; color: inherit; }
    .btn { background: #1f9d5a; color: #fff; border: 0; border-radius: 8px; padding: 8px 12px; font: inherit; font-weight: 600; cursor: pointer; }
    .btn.sec { background: transparent; color: inherit; border: 1px solid #c9c9d9; }
    .banner { position: fixed; top: 16px; right: 16px; z-index: 2147483647; width: 330px; background: #fff; color: #16181d; border-radius: 16px; padding: 16px;
      box-shadow: 0 12px 40px rgba(20,20,50,.25); font: 13px/1.45 system-ui, sans-serif; border: 1px solid #dfe2e7; }
    @media (prefers-color-scheme: dark) { .banner { background: #1c1f26; color: #e6e8eb; border-color: #2a2f38; } }
    .row { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; }
    .dlg-bg { position: fixed; inset: 0; z-index: 2147483647; background: rgba(8,10,14,.45); display: grid; place-items: center; font: 13px/1.45 system-ui, sans-serif; }
    .dlg { width: 360px; max-width: calc(100vw - 32px); background: #fff; color: #16181d; border-radius: 16px; padding: 18px; box-shadow: 0 16px 50px rgba(0,0,0,.35); border: 1px solid #dfe2e7; }
    @media (prefers-color-scheme: dark) { .dlg { background: #1c1f26; color: #e6e8eb; border-color: #2a2f38; } }
    .dlg h3 { margin: 4px 0 6px; font-size: 16px; }
    .dlg .list { margin: 10px 0 0; max-height: 260px; overflow: auto; }
  </style><button class="icon" title="Jace Passwords">${ICON}</button><div class="menu" role="menu"></div><div class="slot"></div>`;
  const iconBtn = root.querySelector(".icon");
  const menu = root.querySelector(".menu");
  let current = null; // { el, kind }

  function attach() { if (!host.isConnected) (document.body || document.documentElement).appendChild(host); }

  function placeIcon() {
    if (!current || !current.el.isConnected) { iconBtn.style.display = "none"; return; }
    const r = current.el.getBoundingClientRect();
    iconBtn.style.display = "block";
    iconBtn.style.left = `${r.right - 26}px`;
    iconBtn.style.top = `${r.top + (r.height - 22) / 2}px`;
    if (menu.style.display === "block") placeMenu();
  }
  function placeMenu() {
    const r = current.el.getBoundingClientRect();
    menu.style.left = `${Math.max(8, Math.min(r.left, innerWidth - 310))}px`;
    const mh = Math.min(menu.scrollHeight || 120, 340);
    menu.style.top = `${r.bottom + 6 + mh > innerHeight && r.top - mh - 6 > 0 ? r.top - mh - 6 : r.bottom + 6}px`;
  }
  const hideMenu = () => (menu.style.display = "none");

  const color = (s) => { let x = 0; for (const c of String(s)) x = (x * 31 + c.charCodeAt(0)) >>> 0; return `hsl(${x % 360} 60% 50%)`; };
  const tile = (title, bg) => `<span class="tile" style="background:${bg || color(title)}">${esc((title || "?")[0].toUpperCase())}</span>`;

  async function openMenu() {
    if (!current) return;
    attach();
    menu.style.display = "block";
    placeMenu();
    menu.innerHTML = `<div class="msg">Loading…</div>`;
    const group = KIND_GROUP(current.kind);
    const st = await send({ type: "status" });
    if (st.error === "offline") return (menu.innerHTML = `<div class="hd">${ICON} Jace Passwords</div><div class="msg">Open the Jace Passwords app to use autofill.</div>`);
    if (st.error === "unpaired") return (menu.innerHTML = `<div class="hd">${ICON} Jace Passwords</div><div class="msg">Click the Jace Passwords toolbar button to connect this browser.</div>`);
    if (st.error === "signedout" || st.error === "novault") return (menu.innerHTML = `<div class="hd">${ICON} Jace Passwords</div><div class="msg">${esc(st.error === "signedout" ? "Click the Jace Passwords toolbar button to sign in with Jace." : "Create your vault in Jace Passwords first.")}</div>`);
    if (st.error) return (menu.innerHTML = `<div class="hd">${ICON} Jace Passwords</div><div class="msg">${esc(st.message || "Something went wrong.")}</div>`);
    if (st.locked) {
      menu.innerHTML = `<div class="hd">${ICON} Jace Passwords is locked</div><form style="padding:4px 8px 8px"><input type="password" placeholder="Master password" autocomplete="off"><div class="msg err" style="padding:2px 0;color:#e03e52"></div><button class="btn" style="width:100%">Unlock</button></form>`;
      const f = menu.querySelector("form");
      f.querySelector("input").focus();
      f.addEventListener("submit", async (e) => {
        e.preventDefault();
        f.querySelector(".btn").textContent = "Unlocking…";
        const r = await send({ type: "unlock", password: f.querySelector("input").value });
        if (r.error) { f.querySelector(".err").textContent = r.message; f.querySelector(".btn").textContent = "Unlock"; }
        else openMenu();
      });
      return;
    }
    const m = await send({ type: "match", url: location.href });
    let html = `<div class="hd">${ICON} Jace Passwords</div>`;
    if (group === "new") {
      const g = await send({ type: "generate", opts: {} });
      html += `<button class="it" data-gen="${esc(g.password)}"><span class="tile" style="background:#1f9d5a">🎲</span><span class="m"><div class="t">Use a strong password</div><div class="pw">${esc(g.password)}</div></span></button>`;
    }
    if (group === "totp") {
      html += `<button class="it" data-totp="1"><span class="tile" style="background:#12a26b">🔢</span><span class="m"><div class="t">Fill 2FA code</div><div class="muted">From the login you just used</div></span></button>`;
      (m.logins || []).filter((l) => l.hasTotp).forEach((l) => (html += `<button class="it" data-id="${esc(l.id)}" data-totp-id="1">${tile(l.title)}<span class="m"><div class="t">2FA · ${esc(l.title)}</div><div class="muted">${esc(l.username)}</div></span></button>`));
    }
    if (group === "login" && conditional && conditional.list.length) {
      conditional.list.forEach((p, n) => (html += `<button class="it" data-pk="${n}">${tile(p.title)}<span class="m"><div class="t">🔑 Passkey · ${esc(p.title)}</div><div class="muted">${esc(p.userName)}</div></span></button>`));
    }
    if (group === "login" || group === "new") {
      const logins = m.logins || [];
      logins.forEach((l) => {
        const sso = l.signInWith ? `Use “Sign in with ${esc(l.signInWith.provider === "other" ? l.signInWith.name || "service" : l.signInWith.provider[0].toUpperCase() + l.signInWith.provider.slice(1))}”${l.signInWith.account ? " · " + esc(l.signInWith.account) : ""}` : "";
        html += `<button class="it" data-id="${esc(l.id)}" ${sso && !l.hasPassword ? "data-sso=1" : ""}>${tile(l.title)}<span class="m"><div class="t">${esc(l.title)}</div><div class="muted">${sso || esc(l.username || "")}</div></span></button>`;
      });
      if (!logins.length && group === "login" && !conditional?.list.length) html += `<div class="msg">No logins saved for ${esc(m.site || location.hostname)} yet. Sign in and Jace Passwords will offer to save it.</div>`;
    }
    if (group === "card") {
      (m.cards || []).forEach((c) => (html += `<button class="it" data-id="${esc(c.id)}"><span class="tile" style="background:#3b46c4">💳</span><span class="m"><div class="t">${esc(c.title)}</div><div class="muted">${esc(c.brand || "Card")} ${c.cardType === "debit" ? "debit" : "credit"} •••• ${esc(c.last4)}</div></span></button>`));
      if (!(m.cards || []).length) html += `<div class="msg">No cards in your vault yet.</div>`;
    }
    if (group === "identity" || group === "login") {
      (m.identities || []).forEach((p) => (html += `<button class="it" data-id="${esc(p.id)}"><span class="tile" style="background:#e8743b">🪪</span><span class="m"><div class="t">${esc(p.title)}</div><div class="muted">${esc(p.name || p.email)}</div></span></button>`));
    }
    menu.innerHTML = html;
    placeMenu();
  }

  menu.addEventListener("click", async (e) => {
    const it = e.target.closest(".it");
    if (!it || !current) return;
    if (it.dataset.pk !== undefined && conditional) {
      const c = conditional;
      conditional = null;
      hideMenu();
      reply(c.id, await send({ type: "passkey-get", req: c.req, credentialId: c.list[+it.dataset.pk].credentialId }));
      return;
    }
    const anchor = current.el;
    if (it.dataset.gen) {
      const scope = anchor.form || document;
      [...scope.querySelectorAll("input[type=password]")].filter(visible).forEach((p) => {
        const k = classify(p);
        if (k === "new-password" || p === anchor) setValue(p, it.dataset.gen);
      });
      if (anchor.type === "password") anchor.type = "password";
      hideMenu();
      return;
    }
    if (it.dataset.totp && !it.dataset.id) {
      const r = await send({ type: "totp-for-tab" });
      if (r.totp) setValue(anchor, r.totp);
      else menu.innerHTML = `<div class="msg">No recent login with a 2FA code on this tab.</div>`;
      if (r.totp) hideMenu();
      return;
    }
    if (it.dataset.sso) { hideMenu(); return; }
    const data = await send({ type: "fill", id: it.dataset.id });
    if (data.error) { menu.innerHTML = `<div class="msg">${esc(data.message)}</div>`; return; }
    if (it.dataset.totpId) { if (data.totp) setValue(anchor, data.totp); }
    else fill(data, anchor);
    hideMenu();
  });

  iconBtn.addEventListener("mousedown", (e) => e.preventDefault());
  iconBtn.addEventListener("click", (e) => { e.preventDefault(); menu.style.display === "block" ? hideMenu() : openMenu(); });

  document.addEventListener("focusin", (e) => {
    const el = e.composedPath()[0];
    if (el === host) return;
    const kind = el instanceof HTMLInputElement ? classify(el) : null;
    if (!kind) { if (!host.contains(el)) { current = null; hideMenu(); placeIcon(); } return; }
    current = { el, kind };
    attach();
    placeIcon();
  }, true);
  document.addEventListener("mousedown", (e) => { if (!e.composedPath().includes(host) && e.target !== current?.el) hideMenu(); }, true);
  addEventListener("scroll", placeIcon, true);
  addEventListener("resize", placeIcon);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideMenu();
    if (e.key === "ArrowDown" && current && e.target === current.el && e.altKey) { e.preventDefault(); openMenu(); }
  }, true);

  /* ---------- messages from the popup / background ---------- */
  B.runtime.onMessage.addListener((msg) => {
    if (msg.type === "do-fill") {
      const anchor = current?.el || document.querySelector("input[type=password]") || document.querySelector("input");
      fill(msg.data, anchor);
    } else if (msg.type === "insert-generated") {
      const el = document.activeElement;
      if (el instanceof HTMLInputElement) {
        setValue(el, msg.password);
        const scope = el.form || document;
        [...scope.querySelectorAll("input[type=password]")].filter((p) => p !== el && classify(p) === "new-password").forEach((p) => setValue(p, msg.password));
      }
    } else if (msg.type === "open-menu") {
      const el = document.activeElement;
      if (el instanceof HTMLInputElement) { current = { el, kind: classify(el) || "username" }; openMenu(); }
    }
  });

  /* ---------- offer to save after you sign in ---------- */
  function capture(form) {
    const scope = form || document;
    const pws = [...scope.querySelectorAll("input[type=password]")].filter((p) => p.value);
    if (!pws.length) return;
    const pw = pws[pws.length - 1].value;
    const users = [...scope.querySelectorAll("input")].filter((i) => ["username", "id-email"].includes(classify(i)) && i.value);
    const username = users[0]?.value || (document.querySelector("input[autocomplete=username]")?.value ?? "");
    send({ type: "submitted", url: location.href, username, password: pw });
  }
  document.addEventListener("submit", (e) => capture(e.target), true);
  document.addEventListener("click", (e) => {
    const b = e.target.closest?.("button, input[type=submit], [role=button]");
    if (!b) return;
    const form = b.form || b.closest("form");
    if (form ? form.querySelector("input[type=password]") : /log.?in|sign.?in|continue|next|submit|register|sign.?up/i.test(b.textContent || b.value || "")) capture(form);
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Enter" && e.target instanceof HTMLInputElement && e.target.type === "password") capture(e.target.form); }, true);

  async function maybeOfferSave() {
    if (window.top !== window) return;
    const p = await send({ type: "pending-save" });
    if (p.none || !p.status) return;
    const site = location.hostname.replace(/^www\./, "");
    if ((await send({ type: "is-never", site })).never) return;
    attach();
    const slot = root.querySelector(".slot");
    slot.innerHTML = `<div class="banner"><div class="hd" style="padding:0 0 6px">${ICON} Jace Passwords</div>
      <b>${p.status === "update" ? "Update the saved password" : "Save this login"} for ${esc(p.title || site)}?</b>
      <div class="muted" style="margin-top:4px">${esc(p.username || "No username")}</div>
      <div class="row"><button class="btn" data-s="save">${p.status === "update" ? "Update" : "Save"}</button><button class="btn sec" data-s="later">Not now</button><button class="btn sec" data-s="never">Never for this site</button></div></div>`;
    slot.querySelector(".banner").addEventListener("click", async (e) => {
      const s = e.target.dataset.s;
      if (!s) return;
      if (s === "never") await send({ type: "never-save", site });
      else await send({ type: "save-pending", save: s === "save" });
      slot.innerHTML = "";
    });
    setTimeout(() => (slot.innerHTML = ""), 30000);
  }

  /* ---------- passkeys (requests come from passkey-page.js in the page's world) ---------- */
  const PK = "jace-passwords-passkey";
  let conditional = null; // a waiting "passkey autofill" sign-in: { id, req, list }
  const dialogs = new Map(); // request id -> close()
  const reply = (id, result) => window.postMessage({ tag: PK, dir: "to-page", id, result }, location.origin);
  const fail = (r) => {
    const m = /^(\w+Error): (.*)$/.exec(r?.message || "");
    return m ? { error: m[1], message: m[2] } : { error: "NotAllowedError", message: r?.message || "Not allowed." };
  };

  function dialog(id, html, wire) {
    attach();
    const wrap = document.createElement("div");
    wrap.className = "dlg-bg";
    wrap.innerHTML = `<div class="dlg" role="dialog"><div class="hd" style="padding:0 0 4px">${ICON} Jace Passwords</div>${html}</div>`;
    root.appendChild(wrap);
    const close = () => { wrap.remove(); dialogs.delete(id); };
    dialogs.set(id, close);
    wire(wrap, close);
  }

  // Unlocked (asking for the master password if needed)? Resolves false to use another device.
  function ready(id) {
    return new Promise(async (resolve) => {
      const st = await send({ type: "status" });
      if (st.error) return resolve(false); // app not running or not paired: let the browser handle it
      if (!st.locked) return resolve(true);
      dialog(id, `<h3>Unlock to use your passkey</h3><form><input type="password" placeholder="Master password" autocomplete="off">
        <div class="err" style="color:#e0464f;min-height:1em"></div><div class="row"><button class="btn">Unlock</button><button type="button" class="btn sec" data-x>Use another device</button></div></form>`,
      (w, close) => {
        const f = w.querySelector("form");
        f.querySelector("input").focus();
        w.querySelector("[data-x]").addEventListener("click", () => { close(); resolve(false); });
        f.addEventListener("submit", async (e) => {
          e.preventDefault();
          const r = await send({ type: "unlock", password: f.querySelector("input").value });
          if (r.error) f.querySelector(".err").textContent = r.message; else { close(); resolve(true); }
        });
      });
    });
  }

  async function onCreate(id, req) {
    if (!(await ready(id))) return reply(id, { fallback: true });
    const site = req.rp.id;
    dialog(id, `<h3>Save a passkey for ${esc(req.rp.name || site)}?</h3>
      <div class="muted" style="white-space:normal">${esc(req.user.name || req.user.displayName || "Your account")} · ${esc(site)}</div>
      <p class="muted" style="white-space:normal">It's stored in your encrypted vault and syncs with your Jace account.</p>
      <div class="row"><button class="btn" data-a="save">Save passkey</button><button class="btn sec" data-a="other">Use another device</button><button class="btn sec" data-a="no">Cancel</button></div>`,
    (w, close) => {
      w.querySelector("[data-a=save]").focus();
      w.addEventListener("click", async (e) => {
        const a = e.target.dataset?.a;
        if (!a) return;
        close();
        if (a === "other") return reply(id, { fallback: true });
        if (a === "no") return reply(id, { error: "NotAllowedError", message: "Cancelled." });
        const r = await send({ type: "passkey-create", req });
        if (r.error) return reply(id, r.error === "offline" ? { fallback: true } : fail(r));
        reply(id, r);
      });
    });
  }

  async function onGet(id, req) {
    if (req.conditional) {
      const st = await send({ type: "status" });
      if (st.error) return reply(id, { fallback: true });
      const list = st.locked ? [] : await send({ type: "passkey-list", req });
      if (!Array.isArray(list) || !list.length) return reply(id, { fallback: true });
      conditional = { id, req, list }; // shown in the field menu; stays waiting like the browser's own
      return;
    }
    if (!(await ready(id))) return reply(id, { fallback: true });
    const list = await send({ type: "passkey-list", req });
    if (!Array.isArray(list) || !list.length) return reply(id, { fallback: true });
    dialog(id, `<h3>Sign in to ${esc(req.rpId)} with a passkey</h3><div class="list">${list.map((p, n) =>
      `<button class="it" data-n="${n}">${tile(p.title)}<span class="m"><div class="t">${esc(p.userName || p.userDisplayName || p.title)}</div><div class="muted">${esc(p.title)}</div></span></button>`).join("")}</div>
      <div class="row"><button class="btn sec" data-a="other">Use another device</button><button class="btn sec" data-a="no">Cancel</button></div>`,
    (w, close) => {
      w.querySelector(".it")?.focus();
      w.addEventListener("click", async (e) => {
        const it = e.target.closest("[data-n],[data-a]");
        if (!it) return;
        close();
        if (it.dataset.a === "other") return reply(id, { fallback: true });
        if (it.dataset.a === "no") return reply(id, { error: "NotAllowedError", message: "Cancelled." });
        const r = await send({ type: "passkey-get", req, credentialId: list[+it.dataset.n].credentialId });
        reply(id, r.error ? fail(r) : r);
      });
    });
  }

  window.addEventListener("message", (e) => {
    if (e.source !== window || e.data?.tag !== PK || e.data.dir !== "to-ext") return;
    const { id, kind, req } = e.data;
    if (kind === "abort") { dialogs.get(id)?.(); if (conditional?.id === id) conditional = null; return; }
    if (kind === "create") onCreate(id, req);
    else if (kind === "get") onGet(id, req);
  });

  maybeOfferSave();
  // single-page apps change pages without a reload
  let lastUrl = location.href;
  setInterval(() => { if (location.href !== lastUrl) { lastUrl = location.href; setTimeout(maybeOfferSave, 800); } }, 1000);
})();
