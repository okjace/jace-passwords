const B = globalThis.browser ?? globalThis.chrome;
const send = (msg) => new Promise((res) => B.runtime.sendMessage(msg, (r) => res(r || {})));
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const color = (s) => { let x = 0; for (const c of String(s)) x = (x * 31 + c.charCodeAt(0)) >>> 0; return `hsl(${x % 360} 60% 50%)`; };
let tab = null, tabName = "site";

async function copy(text, btn) {
  await navigator.clipboard.writeText(text);
  const old = btn.textContent;
  btn.textContent = "✓";
  setTimeout(() => (btn.textContent = old), 1200);
  setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), 30000);
}

async function start() {
  [tab] = await B.tabs.query({ active: true, currentWindow: true });
  const mode = await send({ type: "mode" });
  const st = await send({ type: "status" });
  const main = $("#main");
  $("#lock").classList.add("hidden");
  if (st.error === "offline") {
    main.innerHTML = `<div class="center" style="padding:20px 6px"><div style="font-size:34px">🔐</div><p><b>The Jace Passwords app isn't running</b></p>
      <p class="muted">Open the app on this computer, or use the extension on its own.</p><button class="btn" id="go-solo">Use without the app</button></div>`;
    $("#go-solo").addEventListener("click", async () => { await send({ type: "unpair" }); start(); });
    return;
  }
  if (st.error === "unpaired") return renderPair(main);
  if (st.error === "signedout") {
    main.innerHTML = `<div class="center" style="padding:14px 6px"><div style="font-size:34px">🔐</div><p><b>Sign in to Jace Passwords</b></p>
      <p class="muted">Your vault comes from your Jace account, end-to-end encrypted.</p>
      <button class="btn" id="signin">Sign in with Jace</button><div class="err" id="err"></div>
      <p class="muted" style="margin-top:14px">Have the desktop app? <a id="to-pair" href="#">Connect to it instead</a></p></div>`;
    $("#signin").addEventListener("click", async (e) => {
      e.target.disabled = true; e.target.textContent = "Signing in…";
      const r = await send({ type: "jace-signin" });
      if (r.error) { $("#err").textContent = r.message; e.target.disabled = false; e.target.textContent = "Sign in with Jace"; } else start();
    });
    $("#to-pair").addEventListener("click", (e) => { e.preventDefault(); renderPair(main); });
    return;
  }
  if (st.error === "novault") {
    main.innerHTML = `<div class="center" style="padding:14px 6px"><div style="font-size:34px">✨</div><p><b>Create your vault</b></p>
      <p class="muted">There's no vault on your Jace account yet. Create one in Jace Passwords on the web, then come back here.</p>
      <button class="btn" id="open-web">Open Jace Passwords</button>
      <p class="muted" style="margin-top:12px"><a id="signout" href="#">Sign out</a></p></div>`;
    $("#open-web").addEventListener("click", () => send({ type: "open-web" }));
    $("#signout").addEventListener("click", async (e) => { e.preventDefault(); await send({ type: "jace-signout" }); start(); });
    return;
  }
  $("#who").textContent = st.account ? "@" + st.account.username : "";
  if (st.locked) {
    const info = mode.mode === "standalone" ? await send({ type: "standalone-info" }) : { keyMode: st.keyMode };
    const withJace = info.keyMode === "jace";
    main.innerHTML = `<form id="unlock" class="center" style="padding:10px 4px"><div style="font-size:34px">🔒</div><p><b>Unlock Jace Passwords</b></p>
      ${withJace ? `<p class="muted">This vault unlocks with your Jace account.</p>` : `<input type="password" id="pw" placeholder="Master password" autofocus>`}
      ${info.needsSecretKey ? `<input id="sk" placeholder="Secret Key (J1-…)" autocomplete="off" spellcheck="false" style="margin-top:6px">` : ""}
      <div class="err" id="err"></div><button class="btn">${withJace ? "Unlock with Jace" : "Unlock"}</button></form>`;
    $("#unlock").addEventListener("submit", async (e) => {
      e.preventDefault();
      e.submitter.textContent = "Unlocking…";
      const r = mode.mode === "standalone"
        ? await send({ type: "standalone-unlock", password: $("#pw")?.value || "", secretKey: $("#sk")?.value || "" })
        : await send({ type: "unlock", password: $("#pw")?.value || "" });
      if (r.error) { $("#err").textContent = r.message; e.submitter.textContent = withJace ? "Unlock with Jace" : "Unlock"; } else start();
    });
    return;
  }
  $("#lock").classList.remove("hidden");
  renderMain(mode.mode);
}

function renderPair(main) {
  main.innerHTML = `<form id="pair"><p><b>Connect to the desktop app</b></p><p class="muted">In the Jace Passwords app, go to Settings → Browser extension → Get pairing code.</p>
    <input id="code" inputmode="numeric" maxlength="6" placeholder="6-digit code" autofocus style="text-align:center;font-size:20px;letter-spacing:.3em"><div class="err" id="err"></div><button class="btn">Connect</button>
    <p class="muted" style="margin-top:12px;text-align:center"><a id="solo" href="#">Use the extension on its own instead</a></p></form>`;
  $("#pair").addEventListener("submit", async (e) => {
    e.preventDefault();
    const ua = navigator.userAgent;
    const name = /Firefox/.test(ua) ? "Firefox" : /Edg\//.test(ua) ? "Edge" : /Brave/.test(ua) ? "Brave" : /OPR/.test(ua) ? "Opera" : "Chrome";
    const r = await send({ type: "pair", code: $("#code").value.trim(), name });
    if (r.error) $("#err").textContent = r.message; else start();
  });
  $("#solo").addEventListener("click", async (e) => { e.preventDefault(); await send({ type: "unpair" }); start(); });
}

let currentMode = "desktop";
async function renderMain(mode = currentMode) {
  currentMode = mode;
  const main = $("#main");
  const solo = mode === "standalone";
  main.innerHTML = `<div class="tabs">${[["site", "This site"], ["search", "Search"], ["gen", "Generator"]].map(([k, l]) => `<button data-tab="${k}" class="${tabName === k ? "on" : ""}">${l}</button>`).join("")}</div><div id="body"></div>
    <footer><a id="open">Open Jace Passwords ↗</a><a id="unpair" class="muted">${solo ? "Sign out" : "Disconnect"}</a></footer>`;
  main.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { tabName = b.dataset.tab; renderMain(); }));
  $("#open").addEventListener("click", () => send({ type: solo ? "open-web" : "open-app" }));
  $("#unpair").addEventListener("click", async () => { await send({ type: solo ? "jace-signout" : "unpair" }); start(); });
  const body = $("#body");
  if (tabName === "gen") return renderGen(body);
  if (tabName === "search") {
    body.innerHTML = `<input id="q" placeholder="Search your vault" autofocus><div id="res"></div>`;
    const run = async () => list($("#res"), await send({ type: "search", q: $("#q").value }));
    $("#q").addEventListener("input", run);
    run();
    return;
  }
  const m = await send({ type: "match", url: tab?.url || "" });
  if (m.error) { body.innerHTML = `<p class="err">${esc(m.message)}</p>`; return; }
  body.innerHTML = `<div class="sec">Logins for ${esc(m.site || "this page")}</div><div id="logins"></div><div class="sec">Cards</div><div id="cards"></div>${m.identities?.length ? `<div class="sec">Identities</div><div id="ids"></div>` : ""}`;
  list($("#logins"), m.logins, `<p class="muted" style="padding:0 6px">Nothing saved for this site. Sign in and you'll be asked to save it.</p>`);
  list($("#cards"), m.cards, `<p class="muted" style="padding:0 6px">No cards yet.</p>`);
  if (m.identities?.length) list($("#ids"), m.identities);
}

function list(el, items = [], empty = `<p class="muted center">No matches.</p>`) {
  if (!items.length) { el.innerHTML = empty; return; }
  el.innerHTML = items.map((i) => {
    const icon = i.type === "card" ? "💳" : i.type === "identity" ? "🪪" : i.type === "note" ? "📝" : esc((i.title || "?")[0].toUpperCase());
    const sub = (i.passkeys ? "🗝️ " : "") + (i.type === "card" ? `${i.brand || "Card"} •••• ${i.last4}` : i.signInWith ? `Sign in with ${i.signInWith.provider}` : i.username || i.name || i.alias || "");
    const canFill = ["login", "card", "identity"].includes(i.type);
    return `<div class="it">${`<span class="tile" style="background:${i.type === "card" ? "#3b46c4" : color(i.title)}">${icon}</span>`}
      <div class="m"><div class="t">${esc(i.title)}</div><div class="s">${esc(sub)}</div></div>
      <div class="acts">${i.type === "login" && i.username ? `<button class="ghost" data-copy="user" data-id="${esc(i.id)}" title="Copy username">👤</button>` : ""}
      ${i.hasPassword ? `<button class="ghost" data-copy="password" data-id="${esc(i.id)}" title="Copy password">🔑</button>` : ""}
      ${i.hasTotp ? `<button class="ghost" data-copy="totp" data-id="${esc(i.id)}" title="Copy 2FA code">🔢</button>` : ""}
      ${canFill ? `<button class="ghost" data-fill="${esc(i.id)}" title="Fill">⤵</button>` : ""}</div></div>`;
  }).join("");
  el.querySelectorAll("[data-fill]").forEach((b) => b.addEventListener("click", async () => {
    await send({ type: "fill-in-tab", id: b.dataset.fill, tabId: tab.id });
    window.close();
  }));
  el.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
    const d = await send({ type: "fill", id: b.dataset.id });
    const v = b.dataset.copy === "user" ? d.username : b.dataset.copy === "password" ? d.password : d.totp;
    if (v) copy(v, b);
  }));
}

async function renderGen(body) {
  let opts = { type: "random", length: 20 };
  const draw = async () => {
    const r = await send({ type: "generate", opts });
    body.innerHTML = `<div class="tabs">${[["random", "Random"], ["passphrase", "Passphrase"], ["pin", "PIN"]].map(([k, l]) => `<button data-g="${k}" class="${opts.type === k ? "on" : ""}">${l}</button>`).join("")}</div>
      <div class="gen">${esc(r.password)}</div><p class="muted" style="margin:6px 2px">${esc(r.strength?.label)} · ~${r.strength?.bits} bits</p>
      ${opts.type === "random" ? `<label class="muted">Length ${opts.length}</label><input type="range" min="8" max="64" value="${opts.length}" id="len" style="padding:0;background:none;border:0">` : ""}
      <button class="btn" id="cp">Copy</button><button class="btn" id="again" style="background:var(--panel);color:var(--text)">⟳ New password</button>`;
    body.querySelectorAll("[data-g]").forEach((b) => b.addEventListener("click", () => { opts = { type: b.dataset.g, length: b.dataset.g === "pin" ? 6 : 20 }; draw(); }));
    $("#len")?.addEventListener("change", (e) => { opts.length = +e.target.value; draw(); });
    $("#cp").addEventListener("click", (e) => copy(r.password, e.target));
    $("#again").addEventListener("click", draw);
  };
  draw();
}

$("#lock").addEventListener("click", async () => { await send({ type: "lock" }); start(); });
start();
