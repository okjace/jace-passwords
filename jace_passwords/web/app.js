"use strict";
/* Jace Passwords — app window. Talks only to the local server (/api/*). */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const h = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const TYPES = {
  login: { label: "Login", plural: "Logins", icon: "🔑" },
  card: { label: "Card", plural: "Cards", icon: "💳" },
  note: { label: "Secure note", plural: "Notes", icon: "📝" },
  identity: { label: "Identity", plural: "Identities", icon: "🪪" },
  alias: { label: "Email alias", plural: "Aliases", icon: "📧" },
};
const PROVIDERS = {
  google: { name: "Google", color: "#4285f4", glyph: "G" },
  apple: { name: "Apple", color: "#111111", glyph: "" },
  microsoft: { name: "Microsoft", color: "#00a4ef", glyph: "⊞" },
  github: { name: "GitHub", color: "#24292f", glyph: "🐙" },
  facebook: { name: "Facebook", color: "#1877f2", glyph: "f" },
  x: { name: "X", color: "#000000", glyph: "𝕏" },
  discord: { name: "Discord", color: "#5865f2", glyph: "◉" },
  jace: { name: "Jace", color: "#1f9d5a", glyph: "J" },
  other: { name: "Other service", color: "#6b6b83", glyph: "↪" },
};
const BRAND_COLORS = { Visa: ["#1a1f71", "#3b46c4"], Mastercard: ["#1b1b1b", "#eb001b"], Amex: ["#2e77bb", "#6fb1e8"], Discover: ["#ff6000", "#b33d00"] };

const S = {
  server: null, data: null, view: "all", selected: null, search: "", tag: null,
  watch: null, breach: null, codes: {}, onboard: null, gen: null, filterIds: null, revealed: new Set(),
};

/* ---------------- api ---------------- */
async function api(method, path, body, background = false) {
  if (window.JPWeb) { // the web app: the vault runs in this page (webvault.js)
    try { return await window.JPWeb.api(method, path, body ?? {}); }
    catch (e) { if (e.locked) { await refreshState(); throw new Error("Locked"); } throw e; }
  }
  const headers = { "X-Jace-Passwords": "1" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (background) headers["X-Background"] = "1";
  const r = await fetch("/api/" + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined, credentials: "same-origin" });
  let j = {};
  try { j = await r.json(); } catch { /* empty */ }
  if (r.status === 423) { await refreshState(); throw new Error("Locked"); }
  if (!r.ok) throw new Error(j.message || "Something went wrong.");
  return j;
}
const GET = (p, bg) => api("GET", p, undefined, bg);
const POST = (p, b = {}) => api("POST", p, b);

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 2200);
}

let clipTimer;
async function copy(text, what = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
    const secs = S.server?.settings?.clipboardClearSeconds ?? 30;
    toast(secs ? `${what} — clears in ${secs}s` : what);
    clearTimeout(clipTimer);
    if (secs) clipTimer = setTimeout(() => navigator.clipboard.writeText("").catch(() => {}), secs * 1000);
  } catch { toast("Couldn't copy"); }
}

/* ---------------- helpers ---------------- */
function colorFor(s) {
  let x = 0;
  for (const c of String(s)) x = (x * 31 + c.charCodeAt(0)) >>> 0;
  return `hsl(${x % 360} 60% 50%)`;
}
function hostOf(u) {
  try { return new URL(/^[a-z]+:\/\//i.test(u) ? u : "https://" + u).hostname.replace(/^www\./, ""); } catch { return ""; }
}
function tileFor(i, cls = "") {
  if (i.type === "card") {
    const b = i.fields?.brand || "";
    const [a, c] = BRAND_COLORS[b] || ["#444a6b", "#7c83b8"];
    return `<div class="tile ${cls}" style="background:linear-gradient(135deg,${a},${c})">💳</div>`;
  }
  if (i.type !== "login") return `<div class="tile ${cls}" style="background:${colorFor(i.type + i.title)}">${TYPES[i.type].icon}</div>`;
  const letter = (i.title || hostOf(i.fields?.urls?.[0]) || "?").trim()[0]?.toUpperCase() || "?";
  return `<div class="tile ${cls}" style="background:${colorFor(i.title)}">${h(letter)}</div>`;
}
function subtitle(i) {
  const f = i.fields || {};
  if (i.type === "login" && f.passkeys?.length && !f.password) return `🗝️ Passkey${f.username ? " · " + f.username : ""}`;
  if (i.type === "login") return f.signInWith ? `Sign in with ${PROVIDERS[f.signInWith.provider]?.name || "service"}` : f.username || hostOf(f.urls?.[0]) || "";
  if (i.type === "card") { const n = (f.number || "").replace(/\D/g, ""); return `${f.brand || "Card"} ${f.cardType === "debit" ? "debit" : "credit"} •••• ${n.slice(-4)}`; }
  if (i.type === "note") return (f.body || "").split("\n")[0].slice(0, 60);
  if (i.type === "identity") return f.fullName || f.email || "";
  if (i.type === "alias") return f.alias || "";
  return "";
}
function vaultOf(id) { return S.data?.vaults.find((v) => v.id === id); }
function fmtDate(iso) { return iso ? new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "—"; }
function pwHTML(pw) {
  return [...pw].map((c) => /\d/.test(c) ? `<span class="pw-char-d">${h(c)}</span>` : /[^a-zA-Z0-9]/.test(c) ? `<span class="pw-char-s">${h(c)}</span>` : h(c)).join("");
}
function meterHTML(s) {
  const colors = ["#e0464f", "#f08a3c", "#e3b11c", "#5cc97f", "#1f9d5a"];
  return `<div class="meter"><i style="width:${(s.score + 1) * 20}%;background:${colors[s.score]}"></i></div>
    <div class="small muted" style="margin-top:4px">${h(s.label)}${s.bits ? ` · ~${s.bits} bits` : ""}</div>`;
}
function applyTheme() {
  let t = S.server?.settings?.theme || localStorageGet("theme") || "system";
  if (t === "system" && window.JP_SYSTEM_THEME) t = window.JP_SYSTEM_THEME; // the desktop app tells us
  if (t === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", t);
}
window.JP_applyTheme = applyTheme;
function localStorageGet(k) { try { return localStorage.getItem("jp-" + k); } catch { return null; } }
function localStorageSet(k, v) { try { localStorage.setItem("jp-" + k, v); } catch { /* private mode */ } }

/* ---------------- state ---------------- */
async function refreshState() {
  S.server = await GET("state", true);
  applyTheme();
  if (S.server.setup && !S.server.locked) {
    if (!S.data) await loadData();
  } else {
    S.data = null; S.codes = {}; S.revealed.clear();
  }
  render();
}
async function loadData() {
  S.data = await GET("vault");
  S.codes = await GET("totp-codes", true).catch(() => ({}));
}
async function reload() {
  await loadData();
  S.server = await GET("state", true);
  render();
}

/* ---------------- top-level render ---------------- */
function render() {
  const app = $("#app");
  const st = S.server;
  if (!st) { app.innerHTML = ""; return; }
  if (!st.setup) return renderOnboarding(app);
  if (st.locked) return renderLocked(app);
  renderMain(app);
}

/* ---------------- onboarding ---------------- */
const LOGO = `<div class="logo"><img src="/icon.svg" alt="">Jace Passwords</div>`;

async function renderOnboarding(app) {
  const st = S.server;
  const ob = S.onboard || (S.onboard = { step: "welcome" });
  if (ob.step === "welcome" && st.jace && ob.remote === undefined) {
    ob.remote = null;
    GET("jace/remote").then((r) => { ob.remote = r; render(); }).catch((e) => { ob.remote = { error: e.message }; render(); });
  }
  if (ob.step === "kit") return renderKit(app, ob.secretKey);
  if (ob.step === "create") {
    app.innerHTML = `<div class="center"><form class="card" id="f-create">${LOGO}
      <h1>Create your master password</h1>
      <p class="muted">It's the one password you'll need to remember. Jace never sees it, so nobody can reset it for you.</p>
      <label class="lbl">Master password</label>
      <input class="input" type="password" id="pw1" autocomplete="new-password" autofocus>
      <div id="pw1m">${meterHTML({ score: 0, label: "At least 10 characters", bits: 0 })}</div>
      <label class="lbl">Confirm</label>
      <input class="input" type="password" id="pw2" autocomplete="new-password">
      <div class="error" id="err"></div>
      <button class="btn primary block" style="margin-top:12px">Create vault</button>
      ${st.jace ? `<div class="or">or</div>
      <button type="button" class="btn block" id="skip-pw">Skip: unlock with my Jace account</button>
      <p class="small muted" style="margin-top:6px">No password to remember: you unlock by being signed in to Jace. ⚠ Not end-to-end encrypted: whoever controls the Jace Passwords server, or gets into your Jace account, could open your vault. You can add a master password later in Settings.</p>` : ""}
      <button type="button" class="btn ghost block" data-a="ob-back" style="margin-top:6px">Back</button>
      <p class="small muted" style="margin-top:14px">🔐 ${st.jace
        ? `Your vault is encrypted with AES-256 using a key made from this password, and synced to <b>@${h(st.jace.username)}</b>'s Jace account as unreadable ciphertext. On a new device you just sign in with Jace and enter this password.`
        : "Your vault is encrypted with AES-256 using a key made from this password plus a Secret Key that stays on your devices."}</p>
    </form></div>`;
    $("#skip-pw")?.addEventListener("click", async (e) => {
      e.target.disabled = true; e.target.textContent = "Creating…";
      try { await POST("setup", { skipPassword: true }); S.onboard = null; await refreshState(); toast("Your vault is ready 🎉 It unlocks with your Jace account"); }
      catch (x) { $("#err").textContent = x.message; e.target.disabled = false; e.target.textContent = "Skip: unlock with my Jace account"; }
    });
    $("#pw1").addEventListener("input", async (e) => { $("#pw1m").innerHTML = meterHTML(await POST("strength", { password: e.target.value })); });
    $("#f-create").addEventListener("submit", async (e) => {
      e.preventDefault();
      const a = $("#pw1").value, b = $("#pw2").value;
      if (a.length < 10) return ($("#err").textContent = "Use at least 10 characters.");
      if (a !== b) return ($("#err").textContent = "Those passwords don't match.");
      e.submitter.disabled = true; e.submitter.textContent = "Encrypting…";
      try {
        const r = await POST("setup", { password: a });
        if (r.secretKey) { ob.step = "kit"; ob.secretKey = r.secretKey; render(); }
        else { S.onboard = null; await refreshState(); toast("Your vault is ready 🎉 Unlock it anywhere with Jace + your master password"); }
      }
      catch (x) { $("#err").textContent = x.message; e.submitter.disabled = false; e.submitter.textContent = "Create vault"; }
    });
    return;
  }
  if (ob.step === "restore") {
    app.innerHTML = `<div class="center"><form class="card" id="f-restore">${LOGO}
      <h1>Unlock your vault</h1>
      <p class="muted">Your vault is on your Jace account <b>@${h(st.jace?.username)}</b>. ${ob.remote?.keyMode === "jace" ? "It unlocks with your Jace account." : `Enter your master password${ob.remote?.usesSecretKey ? " and the Secret Key from your Emergency Kit" : ""}.`}</p>
      ${ob.remote?.keyMode === "jace" ? "" : `<label class="lbl">Master password</label><input class="input" type="password" id="pw" autofocus>`}
      ${ob.remote?.usesSecretKey ? `<label class="lbl">Secret Key</label><input class="input mono" id="sk" placeholder="J1-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX" autocomplete="off" spellcheck="false">` : ""}
      <div class="error" id="err"></div>
      <button class="btn primary block" style="margin-top:12px">Unlock</button>
      <button type="button" class="btn ghost block" data-a="ob-back" style="margin-top:6px">Back</button>
    </form></div>`;
    $("#f-restore").addEventListener("submit", async (e) => {
      e.preventDefault();
      e.submitter.disabled = true; e.submitter.textContent = "Unlocking…";
      try { await POST("setup", { mode: "restore", password: $("#pw")?.value || "", secretKey: $("#sk")?.value || "" }); S.onboard = null; await refreshState(); toast("Welcome back"); }
      catch (x) { $("#err").textContent = x.message; e.submitter.disabled = false; e.submitter.textContent = "Unlock"; }
    });
    return;
  }
  // welcome
  let jaceBlock;
  if (st.jace) {
    const r = ob.remote;
    jaceBlock = `<div class="acct" style="border:1px solid var(--line);border-radius:12px;margin:18px 0">${avatarHTML(st.jace)}
      <div class="grow"><b>${h(st.jace.name || st.jace.username)}</b><div class="small muted">@${h(st.jace.username)} · Jace account</div></div>
      <button class="btn ghost small" data-a="jace-signout">Switch</button></div>
      ${r === null ? `<p class="muted">Looking for your vault on Jace…</p>`
        : r?.error ? `<p class="error">${h(r.error)}</p><button class="btn primary block" data-a="ob-create">Create a new vault</button>`
        : r?.exists ? `<button class="btn primary block" data-a="ob-restore">Unlock my vault from Jace</button>`
        : `<button class="btn primary block" data-a="ob-create">Create my vault</button>`}`;
  } else {
    jaceBlock = `<button class="btn block jace-btn" data-a="jace-signin" style="margin-top:20px"><img src="/jace-logo.svg" alt="">Sign in with Jace</button>
      <p class="small muted" style="text-align:center;margin-top:8px">Sync your encrypted vault across all your devices.</p>
      <div class="or">or</div>
      <button class="btn block" data-a="ob-create">Use on this computer only</button>`;
  }
  app.innerHTML = `<div class="center"><div class="card">${LOGO}
    <h1>Every password, card and code. One vault.</h1>
    <p class="muted">Logins with passkeys and built-in 2FA codes, credit & debit cards, secure notes, identities and email aliases — end-to-end encrypted and filled in for you.</p>
    ${jaceBlock}
    ${st.signinError ? `<p class="error">${h(st.signinError)}</p>` : ""}
  </div></div>`;
}

function renderKit(app, sk) {
  const st = S.server;
  app.innerHTML = `<div class="center"><div class="card wide">${LOGO}
    <h1>Save your Emergency Kit</h1>
    <p class="muted">You'll need your Secret Key and master password to sign in on a new device. Print this or store it somewhere safe — offline is best.</p>
    <div class="kit">
      <div class="logo" style="font-size:16px"><img src="/icon.svg" alt="" style="width:28px;height:28px">Jace Passwords Emergency Kit</div>
      <label class="lbl">Jace account</label><div>${st.jace ? `@${h(st.jace.username)}` : "Not linked (this computer only)"}</div>
      <label class="lbl">Secret Key</label><div class="sk mono">${h(sk)}</div>
      <label class="lbl">Master password</label><div style="border-bottom:1px solid var(--muted);height:28px"></div>
      <p class="small muted">Created ${new Date().toLocaleDateString()}</p>
    </div>
    <div class="row"><button class="btn" data-a="kit-copy" data-sk="${h(sk)}">Copy Secret Key</button><button class="btn" data-a="print">Print</button></div>
    <label class="check" style="margin-top:16px"><input type="checkbox" id="kit-ok"> I've saved my Secret Key somewhere safe</label>
    <button class="btn primary block" data-a="kit-done" disabled id="kit-done">Open my vault</button>
  </div></div>`;
  $("#kit-ok").addEventListener("change", (e) => ($("#kit-done").disabled = !e.target.checked));
}

function avatarHTML(u) {
  const letter = (u?.name || u?.username || "?")[0].toUpperCase();
  return `<div class="avatar">${u?.picture ? `<img src="${h(u.picture)}" alt="" referrerpolicy="no-referrer">` : h(letter)}</div>`;
}

function renderLocked(app) {
  const st = S.server;
  const who = st.jace || st.vaultAccount;
  app.innerHTML = `<div class="center"><form class="card" id="f-unlock">${LOGO}
    <div style="text-align:center;margin-top:26px">
      <div style="display:inline-block">${who ? avatarHTML(who).replace('class="avatar"', 'class="avatar" style="width:64px;height:64px;font-size:26px"') : `<div style="font-size:48px">🔒</div>`}</div>
      <h1 style="margin-top:12px">${who ? `Welcome back, ${h(who.name || who.username)}` : "Unlock Jace Passwords"}</h1>
      ${who ? `<p class="muted">@${h(who.username)}</p>` : ""}
    </div>
    ${st.keyMode === "jace" ? `<p class="muted" style="text-align:center">This vault unlocks with your Jace account.</p>` : `<label class="lbl">Master password</label>
    <input class="input" type="password" id="pw" autocomplete="current-password" autofocus>`}
    ${!st.needsSecretKey ? "" : `<label class="lbl">Secret Key</label><input class="input mono" id="sk" placeholder="J1-…" autocomplete="off" spellcheck="false">`}
    <div class="error" id="err"></div>
    <button class="btn primary block" style="margin-top:10px" ${st.keyMode === "jace" ? "autofocus" : ""}>${st.keyMode === "jace" ? "Unlock with Jace" : "Unlock"}</button>
  </form></div>`;
  $("#f-unlock").addEventListener("submit", async (e) => {
    e.preventDefault();
    e.submitter.disabled = true; e.submitter.textContent = "Unlocking…";
    try { await POST("unlock", { password: $("#pw")?.value || "", secretKey: $("#sk")?.value }); await refreshState(); }
    catch (x) { $("#err").textContent = x.message; e.submitter.disabled = false; e.submitter.textContent = st.keyMode === "jace" ? "Unlock with Jace" : "Unlock"; $("#pw")?.select(); }
  });
}

/* ---------------- main ---------------- */
function liveItems() { return (S.data?.items || []).filter((i) => !i.deletedAt); }
function currentItems() {
  let items;
  const v = S.view;
  if (v === "trash") items = S.data.items.filter((i) => i.deletedAt);
  else {
    items = liveItems();
    if (v === "favorites") items = items.filter((i) => i.favorite);
    else if (v.startsWith("type:")) items = items.filter((i) => i.type === v.slice(5));
    else if (v.startsWith("vault:")) items = items.filter((i) => i.vaultId === v.slice(6));
    else if (v === "2fa") items = items.filter((i) => i.fields?.totp);
    else if (v === "passkeys") items = items.filter((i) => i.fields?.passkeys?.length);
  }
  if (S.filterIds) items = items.filter((i) => S.filterIds.ids.includes(i.id));
  if (S.tag) items = items.filter((i) => (i.tags || []).includes(S.tag));
  const q = S.search.trim().toLowerCase();
  if (q) items = items.filter((i) => [i.title, i.fields?.username, ...(i.fields?.urls || []), i.fields?.alias, i.fields?.email, ...(i.tags || [])].join(" ").toLowerCase().includes(q));
  return items.sort((a, b) => (b.favorite - a.favorite) || a.title.localeCompare(b.title, undefined, { sensitivity: "base" }));
}

function navBtn(view, icon, label, count) {
  return `<button class="it ${S.view === view ? "on" : ""}" data-a="nav" data-v="${h(view)}"><span>${icon}</span><span>${h(label)}</span>${count !== undefined ? `<span class="count">${count}</span>` : ""}</button>`;
}

function renderMain(app) {
  const st = S.server, d = S.data;
  const live = liveItems();
  const count = (fn) => live.filter(fn).length;
  const tags = [...new Set(live.flatMap((i) => i.tags || []))].sort();
  const isPage = ["generator", "watchtower", "settings"].includes(S.view);
  const sync = st.sync || {};
  const side = `<aside class="side">
    <div class="top"><img src="/icon.svg" alt="">Jace Passwords
      <button class="btn ghost icon" style="margin-left:auto" data-a="lock" title="Lock (Ctrl+L)">🔒</button></div>
    <div style="padding:0 14px 6px"><button class="btn primary block" data-a="new">＋ New item</button></div>
    <nav class="nav">
      ${navBtn("all", "🗂️", "All items", live.length)}
      ${navBtn("favorites", "⭐", "Favorites", count((i) => i.favorite))}
      <div class="sec">Categories</div>
      ${Object.entries(TYPES).map(([k, t]) => navBtn("type:" + k, t.icon, t.plural, count((i) => i.type === k))).join("")}
      ${navBtn("2fa", "🔢", "2FA codes", count((i) => i.fields?.totp))}
      ${navBtn("passkeys", "🗝️", "Passkeys", count((i) => i.fields?.passkeys?.length))}
      <div class="sec">Tools</div>
      ${navBtn("watchtower", "🛡️", "Watchtower")}
      ${navBtn("generator", "🎲", "Password generator")}
      <div class="sec">Vaults ${st.settings?.travelMode ? `<span class="pill warn" title="Travel Mode is on">✈ Travel</span>` : ""}<button class="btn ghost icon small" data-a="new-vault" title="New vault">＋</button></div>
      ${d.vaults.map((v) => `<button class="it ${S.view === "vault:" + v.id ? "on" : ""}" data-a="nav" data-v="vault:${h(v.id)}"><span class="dot" style="background:${h(v.color)}"></span><span>${h(v.icon)} ${h(v.name)}</span><span class="count">${count((i) => i.vaultId === v.id)}</span></button>`).join("")}
      ${tags.length ? `<div class="sec">Tags</div>${tags.map((t) => `<button class="it ${S.tag === t ? "on" : ""}" data-a="tag" data-t="${h(t)}"># ${h(t)}</button>`).join("")}` : ""}
      <div class="sec"></div>
      ${navBtn("trash", "🗑️", "Trash", d.items.filter((i) => i.deletedAt).length)}
      ${navBtn("settings", "⚙️", "Settings")}
    </nav>
    <div class="foot">
      ${st.jace ? `<div class="acct">${avatarHTML(st.jace)}<div style="min-width:0"><b>${h(st.jace.name || st.jace.username)}</b>
        <div class="sync"><span class="s ${h(sync.status)}"></span>${sync.status === "synced" ? "Synced with Jace" : sync.status === "syncing" ? "Syncing…" : sync.status === "error" ? `<span title="${h(sync.error)}">Sync problem</span>` : "Jace account"}</div></div>
        <button class="btn ghost icon" data-a="sync" title="Sync now" style="margin-left:auto">⟳</button></div>`
        : `<button class="btn block jace-btn" data-a="jace-signin"><img src="/jace-logo.svg" alt="">Sign in with Jace to sync</button>`}
    </div>
  </aside>`;

  if (isPage) {
    app.innerHTML = `<div class="layout">${side}<main class="page"><div class="inner" id="page"></div></main></div>`;
    ({ generator: renderGenerator, watchtower: renderWatchtower, settings: renderSettings })[S.view]($("#page"));
    return;
  }

  const items = currentItems();
  if (S.selected && !items.find((i) => i.id === S.selected)) S.selected = null;
  const title = S.view === "all" ? "All items" : S.view === "favorites" ? "Favorites" : S.view === "trash" ? "Trash" : S.view === "2fa" ? "2FA codes" : S.view === "passkeys" ? "Passkeys" : S.view === "passkeys" ? "Passkeys"
    : S.view.startsWith("type:") ? TYPES[S.view.slice(5)].plural : vaultOf(S.view.slice(6))?.name || "";
  const list = `<section class="list">
    <div class="head"><input class="input" id="search" placeholder="Search ${h(title.toLowerCase())}  (Ctrl+K)" value="${h(S.search)}" autocomplete="off">
      ${S.view === "trash" && items.length ? `<button class="btn danger" data-a="empty-trash">Empty</button>` : ""}</div>
    ${S.filterIds ? `<div style="padding:8px 14px" class="row"><span class="pill warn grow">${h(S.filterIds.label)}</span><button class="btn ghost small" data-a="clear-filter">✕</button></div>` : ""}
    ${S.tag ? `<div style="padding:8px 14px" class="row"><span class="pill grow"># ${h(S.tag)}</span><button class="btn ghost small" data-a="tag" data-t="${h(S.tag)}">✕</button></div>` : ""}
    <div class="items" id="items">${items.length ? items.map((i) => `
      <div class="li ${S.selected === i.id ? "on" : ""}" data-a="select" data-id="${h(i.id)}">
        ${tileFor(i)}<div class="meta"><div class="t">${i.favorite ? "⭐ " : ""}${h(i.title)}</div><div class="s">${h(subtitle(i))}</div></div>
        ${S.view === "2fa" ? `<span class="mono" data-code="${h(i.id)}" style="font-weight:700">${h(S.codes[i.id]?.code || "")}</span>` : ""}
      </div>`).join("") : `<div class="empty"><div class="big">${S.view === "trash" ? "🗑️" : "✨"}</div><p>${S.search ? "Nothing matches your search." : S.view === "trash" ? "Trash is empty." : "Nothing here yet."}</p>
        ${S.view !== "trash" && !S.search ? `<button class="btn primary" data-a="new">Add an item</button>` : ""}</div>`}</div>
  </section>`;
  const sel = items.find((i) => i.id === S.selected);
  app.innerHTML = `<div class="layout ${sel ? "show-detail" : ""}">${side}${list}<main class="detail" id="detail">${sel ? detailHTML(sel) : `<div class="empty" style="padding-top:20vh"><div class="big">🔐</div><p>Select an item to see it here.</p><p class="small">Ctrl+K search · Ctrl+N new · Ctrl+L lock</p></div>`}</main></div>`;
  $("#search").addEventListener("input", (e) => {
    S.search = e.target.value;
    const pos = e.target.selectionStart;
    renderMain(app);
    const s = $("#search"); s.focus(); s.setSelectionRange(pos, pos);
  });
  tickTotp();
}

/* ---------------- item detail ---------------- */
function fieldRow(label, value, { secret = false, copyable = true, mono = false, id = "", html = null } = {}) {
  if (!value && !html) return "";
  const key = id + ":" + label;
  const shown = !secret || S.revealed.has(key);
  const display = html ?? (secret ? (shown ? pwHTML(value) : "••••••••••••") : h(value));
  return `<div class="field"><div class="body"><div class="k">${h(label)}</div><div class="v ${mono || secret ? "mono" : ""}">${display}</div></div>
    <div class="tools">${secret ? `<button class="btn ghost icon" data-a="reveal" data-k="${h(key)}" title="${shown ? "Hide" : "Reveal"}">${shown ? "🙈" : "👁️"}</button>` : ""}
    ${copyable ? `<button class="btn ghost icon" data-a="copy" data-val="${h(value)}" data-what="${h(label)} copied" title="Copy">⧉</button>` : ""}</div></div>`;
}

function ringHTML(c) {
  const r = 10, circ = 2 * Math.PI * r;
  const frac = c ? c.remaining / c.period : 0;
  return `<svg class="ring ${c && c.remaining <= 5 ? "low" : ""}" viewBox="0 0 26 26"><circle class="bg" cx="13" cy="13" r="${r}"/><circle class="fg" cx="13" cy="13" r="${r}" stroke-dasharray="${circ}" stroke-dashoffset="${circ * (1 - frac)}"/></svg>`;
}

function detailHTML(i) {
  const f = i.fields || {};
  const vault = vaultOf(i.vaultId);
  const w = S.watch;
  const flags = [];
  if (w && i.type === "login") {
    if (w.weak.includes(i.id)) flags.push(`<span class="pill bad">Weak password</span>`);
    if (w.reused.includes(i.id)) flags.push(`<span class="pill bad">Reused password</span>`);
    if (w.old.includes(i.id)) flags.push(`<span class="pill warn">Over a year old</span>`);
    if (w.missing2fa.includes(i.id)) flags.push(`<span class="pill warn">Two-factor available</span>`);
    if (w.insecure.includes(i.id)) flags.push(`<span class="pill warn">Not HTTPS</span>`);
  }
  if (S.breach?.breached?.[i.id]) flags.push(`<span class="pill bad">Found in ${S.breach.breached[i.id].toLocaleString()} breaches</span>`);
  if (w?.expiring?.includes(i.id)) flags.push(`<span class="pill warn">Expiring soon</span>`);

  let body = "";
  if (i.type === "login") {
    const p = f.signInWith && PROVIDERS[f.signInWith.provider];
    body += `<div class="fields">
      ${fieldRow("Username", f.username)}
      ${fieldRow("Password", f.password, { secret: true, id: i.id })}
      ${f.totp ? `<div class="field"><div class="body"><div class="k">One-time password (2FA)</div>
        <div class="row"><span class="totp mono" data-code="${h(i.id)}">${h(fmtCode(S.codes[i.id]?.code))}</span><span data-ring="${h(i.id)}">${ringHTML(S.codes[i.id])}</span></div></div>
        <div class="tools"><button class="btn ghost icon" data-a="copy-totp" data-id="${h(i.id)}" title="Copy code">⧉</button></div></div>` : ""}
      ${p ? `<div class="field"><div class="body"><div class="k">Sign in with</div><div style="margin-top:6px" class="provider"><span class="tile" style="width:24px;height:24px;font-size:13px;border-radius:6px;background:${p.color}">${h(p.glyph)}</span>${h(f.signInWith.provider === "other" && f.signInWith.name ? f.signInWith.name : p.name)}${f.signInWith.account ? `<span class="muted" style="font-weight:400">· ${h(f.signInWith.account)}</span>` : ""}</div></div></div>` : ""}
    </div>`;
    if ((f.passkeys || []).length) body += `<div class="fields">${f.passkeys.map((p) => `<div class="field"><span style="font-size:20px">🗝️</span><div class="body"><div class="k">Passkey</div>
      <div class="v">${h(p.userName || p.userDisplayName || f.username || "")} <span class="muted">· ${h(p.rpId)}</span></div>
      <div class="small muted">Created ${fmtDate(p.createdAt)}${p.lastUsedAt ? ` · Last used ${fmtDate(p.lastUsedAt)}` : ""}</div></div>
      ${i.deletedAt ? "" : `<div class="tools"><button class="btn ghost icon" data-a="del-passkey" data-id="${h(i.id)}" data-cred="${h(p.credentialId)}" title="Delete passkey">🗑️</button></div>`}</div>`).join("")}</div>`;
    if ((f.urls || []).length) body += `<div class="fields">${f.urls.map((u, n) => `<div class="field"><div class="body"><div class="k">${n ? "Website" : "Website"}</div><div class="v">${h(u)}</div></div>
      <div class="tools"><a class="btn ghost icon" href="${h(/^https?:\/\//i.test(u) ? u : "https://" + u)}" target="_blank" rel="noopener noreferrer" title="Open">↗</a><button class="btn ghost icon" data-a="copy" data-val="${h(u)}" data-what="Website copied">⧉</button></div></div>`).join("")}</div>`;
  } else if (i.type === "card") {
    const n = (f.number || "").replace(/\D/g, "");
    const [a, c] = BRAND_COLORS[f.brand] || ["#3b3f63", "#7c83b8"];
    const showNum = S.revealed.has(i.id + ":num");
    body += `<div class="ccard" style="background:linear-gradient(135deg,${a},${c})">
      <div class="row"><div class="chip"></div><b style="margin-left:auto;font-size:16px">${h(f.brand || "")}</b></div>
      <div class="num mono">${showNum ? h(n.replace(/(.{4})/g, "$1 ").trim()) : "•••• •••• •••• " + h(n.slice(-4))}</div>
      <div class="row2"><div><div style="opacity:.7;font-size:10px">Cardholder</div>${h(f.cardholder || "")}</div><div><div style="opacity:.7;font-size:10px">Expires</div>${h(f.expMonth || "")}/${h(String(f.expYear || "").slice(-2))}</div><div>${f.cardType === "debit" ? "Debit" : "Credit"}</div></div>
    </div>
    <div class="fields">
      ${fieldRow("Cardholder name", f.cardholder)}
      ${fieldRow("Card number", n, { secret: true, id: i.id, mono: true })}
      ${fieldRow("Expiry", f.expMonth || f.expYear ? `${f.expMonth || ""}/${f.expYear || ""}` : "")}
      ${fieldRow("Security code (CVV)", f.cvv, { secret: true, id: i.id })}
      ${fieldRow("PIN", f.pin, { secret: true, id: i.id })}
      ${fieldRow("Billing ZIP / postcode", f.zip)}
      ${fieldRow("Type", f.cardType === "debit" ? "Debit card" : "Credit card", { copyable: false })}
    </div>`;
  } else if (i.type === "note") {
    body += `<div class="fields"><div class="field"><div class="body"><div class="v" style="word-break:break-word">${h(f.body || "")}</div></div><div class="tools"><button class="btn ghost icon" data-a="copy" data-val="${h(f.body || "")}" data-what="Note copied">⧉</button></div></div></div>`;
  } else if (i.type === "identity") {
    body += `<div class="fields">${[["Full name", "fullName"], ["Email", "email"], ["Phone", "phone"], ["Birthday", "birthday"], ["Company", "company"]].map(([l, k]) => fieldRow(l, f[k])).join("")}</div>
      <div class="fields">${[["Address", "address1"], ["Address line 2", "address2"], ["City", "city"], ["State / region", "state"], ["ZIP / postcode", "zip"], ["Country", "country"]].map(([l, k]) => fieldRow(l, f[k])).join("")}</div>`;
  } else if (i.type === "alias") {
    body += `<div class="fields">${fieldRow("Alias", f.alias, { mono: true })}${fieldRow("Forwards to", f.forwardsTo)}</div>`;
  }
  if (f.notes) body += `<div class="fields"><div class="field"><div class="body"><div class="k">Notes</div><div class="v" style="word-break:break-word">${h(f.notes)}</div></div></div></div>`;
  if ((f.custom || []).length) body += `<div class="fields">${f.custom.map((c, n) => fieldRow(c.label || "Field", c.value, { secret: c.hidden, id: i.id + n })).join("")}</div>`;
  if ((i.passwordHistory || []).length) body += `<details class="panel"><summary style="cursor:pointer;font-weight:600">Password history (${i.passwordHistory.length})</summary>
    ${i.passwordHistory.map((p, n) => `<div class="field" style="padding:10px 0">${fieldRow(fmtDate(p.changedAt), p.password, { secret: true, id: i.id + "h" + n }).replace(/^<div class="field">|<\/div>$/g, "")}</div>`).join("")}</details>`;

  const trash = !!i.deletedAt;
  return `<div class="inner">
    <button class="btn ghost mobile-back" data-a="deselect">← Back</button>
    <div class="dhead">${tileFor(i, "lg")}<div style="min-width:0"><h2>${h(i.title)}</h2>
      <div class="muted small">${TYPES[i.type].icon} ${TYPES[i.type].label} · ${vault ? `${h(vault.icon)} ${h(vault.name)}` : ""}</div></div>
      <div class="actions">${trash ? `<button class="btn" data-a="restore" data-id="${h(i.id)}">Restore</button><button class="btn danger" data-a="purge" data-id="${h(i.id)}">Delete forever</button>`
        : `<button class="btn ghost icon" data-a="fav" data-id="${h(i.id)}" title="Favorite">${i.favorite ? "⭐" : "☆"}</button><button class="btn" data-a="edit" data-id="${h(i.id)}">Edit</button><button class="btn ghost icon" data-a="trash" data-id="${h(i.id)}" title="Move to Trash">🗑️</button>`}</div></div>
    ${flags.length ? `<div class="row" style="flex-wrap:wrap;margin-bottom:14px">${flags.join("")}</div>` : ""}
    ${body}
    ${(i.tags || []).length ? `<div class="row" style="flex-wrap:wrap;margin-bottom:14px">${i.tags.map((t) => `<button class="pill" style="border:0;cursor:pointer" data-a="tag" data-t="${h(t)}"># ${h(t)}</button>`).join("")}</div>` : ""}
    <p class="small muted">Created ${fmtDate(i.createdAt)} · Edited ${fmtDate(i.updatedAt)}${i.lastUsedAt ? ` · Last filled ${fmtDate(i.lastUsedAt)}` : ""}</p>
  </div>`;
}
const fmtCode = (c) => (c ? (c.length === 6 ? c.slice(0, 3) + " " + c.slice(3) : c) : "••• •••");

/* ---------------- TOTP ticker ---------------- */
let lastWindow = 0;
async function tickTotp() {
  if (!S.data) return;
  const now = Date.now() / 1000;
  const win = Math.floor(now / 30);
  if (win !== lastWindow) {
    lastWindow = win;
    S.codes = await GET("totp-codes", true).catch(() => S.codes);
  }
  for (const [id, c] of Object.entries(S.codes)) {
    c.remaining = c.period - Math.floor(now % c.period);
    $$(`[data-code="${id}"]`).forEach((el) => (el.textContent = el.classList.contains("totp") ? fmtCode(c.code) : c.code));
    $$(`[data-ring="${id}"]`).forEach((el) => (el.innerHTML = ringHTML(c)));
  }
}
setInterval(tickTotp, 1000);

/* ---------------- item editor ---------------- */
function modal(html, onMount) {
  const root = $("#modal-root");
  root.innerHTML = `<div class="backdrop" data-a="modal-bg">${html}</div>`;
  onMount?.(root);
  $("input,textarea,select", root)?.focus();
}
function closeModal() { $("#modal-root").innerHTML = ""; }

function pickType() {
  modal(`<div class="modal"><div class="mh"><h3>New item</h3><button class="btn ghost icon" data-a="close">✕</button></div>
    <div class="mb"><div class="typepick">${Object.entries(TYPES).map(([k, t]) => `<button data-a="new-type" data-type="${k}"><span class="e">${t.icon}</span><b>${t.label}</b></button>`).join("")}</div></div></div>`);
}

function inp(id, label, value = "", attrs = "") {
  return `<label class="lbl" for="${id}">${label}</label><input class="input" id="${id}" value="${h(value)}" ${attrs}>`;
}

function editItem(item, type) {
  const isNew = !item;
  type = item?.type || type;
  const f = item?.fields || {};
  const vaults = S.data.vaults;
  const defVault = item?.vaultId || (S.view.startsWith("vault:") ? S.view.slice(6) : vaults[0].id);
  let fields = "";
  if (type === "login") {
    const sw = f.signInWith || {};
    fields = `
      <div class="seg" style="margin-top:14px" id="login-mode"><button type="button" class="${sw.provider ? "" : "on"}" data-mode="pw">Password</button><button type="button" class="${sw.provider ? "on" : ""}" data-mode="sso">Sign in with…</button></div>
      <div id="sso-box" class="${sw.provider ? "" : "hidden"}">
        <label class="lbl">Service you sign in with</label>
        <select class="input" id="f-provider">${Object.entries(PROVIDERS).map(([k, p]) => `<option value="${k}" ${sw.provider === k ? "selected" : ""}>${h(p.name)}</option>`).join("")}</select>
        <div id="sso-other" class="${sw.provider === "other" ? "" : "hidden"}">${inp("f-provider-name", "Service name", sw.name || "")}</div>
        ${inp("f-sso-account", "Account used (email or username)", sw.account || "")}
      </div>
      <div class="row"><div class="grow">${inp("f-username", "Username or email", f.username || "", 'autocomplete="off"')}</div>
        <button type="button" class="btn" data-a="make-alias" style="margin-top:30px" title="Make an email alias">📧 Alias</button></div>
      <label class="lbl" for="f-password">Password</label>
      <div class="row"><input class="input mono grow" id="f-password" type="password" value="${h(f.password || "")}" autocomplete="new-password">
        <button type="button" class="btn icon" data-a="toggle-pw" title="Show">👁️</button><button type="button" class="btn" data-a="gen-into" title="Generate a password">🎲 Generate</button></div>
      <div id="pw-meter"></div>
      <label class="lbl">Websites</label><div id="urls">${(f.urls?.length ? f.urls : [""]).map((u) => `<input class="input url-in" style="margin-bottom:6px" value="${h(u)}" placeholder="https://example.com">`).join("")}</div>
      <button type="button" class="btn ghost small" data-a="add-url">＋ Add website</button>
      <label class="lbl" for="f-totp">Two-factor code (2FA)</label>
      <div class="row"><input class="input mono grow" id="f-totp" value="${h(f.totp || "")}" placeholder="Setup key or otpauth:// link" autocomplete="off" spellcheck="false">
        <label class="btn" title="Read a QR code screenshot">📷 QR<input type="file" accept="image/*" id="qr-file" hidden></label></div>
      <div class="small muted" id="totp-preview"></div>`;
  } else if (type === "card") {
    fields = `${inp("f-cardholder", "Cardholder name", f.cardholder || "", 'autocomplete="off"')}
      <label class="lbl" for="f-number">Card number</label><input class="input mono" id="f-number" value="${h(f.number || "")}" inputmode="numeric" autocomplete="off"><div class="small muted" id="card-check"></div>
      <div class="grid3"><div>${inp("f-expMonth", "Exp. month", f.expMonth || "", 'placeholder="MM" inputmode="numeric" maxlength="2"')}</div><div>${inp("f-expYear", "Exp. year", f.expYear || "", 'placeholder="YYYY" inputmode="numeric" maxlength="4"')}</div><div>${inp("f-cvv", "CVV", f.cvv || "", 'inputmode="numeric" maxlength="4" type="password" autocomplete="off"')}</div></div>
      <div class="grid3"><div>${inp("f-pin", "PIN", f.pin || "", 'inputmode="numeric" type="password" autocomplete="off"')}</div><div>${inp("f-zip", "Billing ZIP", f.zip || "")}</div>
        <div><label class="lbl">Type</label><select class="input" id="f-cardType"><option value="credit">Credit</option><option value="debit" ${f.cardType === "debit" ? "selected" : ""}>Debit</option></select></div></div>`;
  } else if (type === "note") {
    fields = `<label class="lbl" for="f-body">Note</label><textarea class="input" id="f-body" style="min-height:220px">${h(f.body || "")}</textarea>`;
  } else if (type === "identity") {
    fields = `${inp("f-fullName", "Full name", f.fullName)}<div class="grid2"><div>${inp("f-email", "Email", f.email, 'type="email"')}</div><div>${inp("f-phone", "Phone", f.phone, 'type="tel"')}</div></div>
      <div class="grid2"><div>${inp("f-birthday", "Birthday", f.birthday, 'type="date"')}</div><div>${inp("f-company", "Company", f.company)}</div></div>
      ${inp("f-address1", "Address", f.address1)}${inp("f-address2", "Address line 2", f.address2)}
      <div class="grid2"><div>${inp("f-city", "City", f.city)}</div><div>${inp("f-state", "State / region", f.state)}</div></div>
      <div class="grid2"><div>${inp("f-zip", "ZIP / postcode", f.zip)}</div><div>${inp("f-country", "Country", f.country)}</div></div>`;
  } else if (type === "alias") {
    fields = `<div class="row"><div class="grow">${inp("f-alias", "Alias address", f.alias)}</div><button type="button" class="btn" data-a="make-alias" style="margin-top:30px">🎲 New alias</button></div>
      ${inp("f-forwardsTo", "Forwards to", f.forwardsTo || S.server.settings?.aliasBase || "", 'type="email"')}
      <p class="small muted">Aliases use plus-addressing (you+shop.ab12@gmail.com), which Gmail, Outlook, iCloud, Proton and Fastmail deliver to your inbox. Give each site its own alias to spot leaks and filter spam.</p>`;
  }
  const custom = (f.custom || []).map(customRow).join("");
  modal(`<form class="modal" id="f-item"><div class="mh"><span style="font-size:20px">${TYPES[type].icon}</span><h3>${isNew ? "New" : "Edit"} ${TYPES[type].label.toLowerCase()}</h3><button type="button" class="btn ghost icon" data-a="close">✕</button></div>
    <div class="mb">
      ${inp("f-title", "Title", item?.title || "", 'required autocomplete="off"')}
      ${fields}
      ${type !== "note" ? `<label class="lbl" for="f-notes">Notes</label><textarea class="input" id="f-notes">${h(f.notes || "")}</textarea>` : ""}
      <label class="lbl">Custom fields</label><div id="customs">${custom}</div>
      <button type="button" class="btn ghost small" data-a="add-custom">＋ Add field</button>
      <div class="grid2"><div><label class="lbl">Vault</label><select class="input" id="f-vault">${vaults.map((v) => `<option value="${h(v.id)}" ${v.id === defVault ? "selected" : ""}>${h(v.icon)} ${h(v.name)}</option>`).join("")}</select></div>
        <div>${inp("f-tags", "Tags (comma separated)", (item?.tags || []).join(", "))}</div></div>
      <label class="check"><input type="checkbox" id="f-fav" ${item?.favorite ? "checked" : ""}> ⭐ Favorite</label>
      <div class="error" id="err"></div>
    </div>
    <div class="mf"><button type="button" class="btn" data-a="close">Cancel</button><button class="btn primary">${isNew ? "Save" : "Save changes"}</button></div></form>`, (root) => mountEditor(root, item, type));
}
function customRow(c = {}) {
  return `<div class="cf"><input class="input cf-l" placeholder="Label" value="${h(c.label || "")}"><input class="input cf-v" placeholder="Value" value="${h(c.value || "")}">
    <label class="check" title="Hide value"><input type="checkbox" class="cf-h" ${c.hidden ? "checked" : ""}>🔒</label><button type="button" class="btn ghost icon" data-a="rm-custom">✕</button></div>`;
}

function mountEditor(root, item, type) {
  const form = $("#f-item", root);
  const val = (id) => $("#" + id, root)?.value?.trim() ?? "";
  if (type === "login") {
    $$("#login-mode button", root).forEach((b) => b.addEventListener("click", () => {
      $$("#login-mode button", root).forEach((x) => x.classList.toggle("on", x === b));
      $("#sso-box", root).classList.toggle("hidden", b.dataset.mode !== "sso");
    }));
    $("#f-provider", root).addEventListener("change", (e) => $("#sso-other", root).classList.toggle("hidden", e.target.value !== "other"));
    const meter = async () => { const p = val("f-password"); $("#pw-meter", root).innerHTML = p ? meterHTML(await POST("strength", { password: p })) : ""; };
    $("#f-password", root).addEventListener("input", meter); meter();
    const tp = async () => {
      const v = val("f-totp");
      if (!v) return ($("#totp-preview", root).textContent = "");
      try { const c = await POST("totp/parse", { value: v }); $("#totp-preview", root).textContent = `✓ ${c.digits}-digit codes every ${c.period}s${c.issuer ? " · " + c.issuer : ""}`; }
      catch (e) { $("#totp-preview", root).textContent = "⚠ " + e.message; }
    };
    $("#f-totp", root).addEventListener("change", tp); tp();
    $("#qr-file", root).addEventListener("change", async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (!("BarcodeDetector" in window)) return toast("This browser can't read QR codes — paste the setup key instead.");
      try {
        const bmp = await createImageBitmap(file);
        const codes = await new window.BarcodeDetector({ formats: ["qr_code"] }).detect(bmp);
        const hit = codes.find((c) => c.rawValue.startsWith("otpauth://"));
        if (!hit) return toast("No 2FA QR code found in that image.");
        $("#f-totp", root).value = hit.rawValue; tp(); toast("2FA code added");
      } catch { toast("Couldn't read that image."); }
    });
    if (!item) $("#f-title", root).addEventListener("blur", () => {
      const first = $(".url-in", root);
      const t = val("f-title");
      if (first && !first.value && /\.[a-z]{2,}$/i.test(t)) first.value = "https://" + t.toLowerCase();
    });
  }
  if (type === "card") {
    const chk = async () => {
      const n = val("f-number").replace(/\D/g, "");
      if (!n) return ($("#card-check", root).textContent = "");
      const r = await POST("card-check", { number: n });
      $("#card-check", root).textContent = `${r.brand || "Unknown brand"}${n.length >= 12 ? (r.valid ? " · ✓ number looks valid" : " · ⚠ check the number") : ""}`;
      root._brand = r.brand;
    };
    $("#f-number", root).addEventListener("input", chk); chk();
  }
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const fields = { ...(item?.fields || {}) };
    const set = (k) => (fields[k] = val("f-" + k));
    if (type === "login") {
      ["username", "totp"].forEach(set);
      fields.password = $("#f-password", root).value;
      fields.urls = $$(".url-in", root).map((x) => x.value.trim()).filter(Boolean);
      const sso = $("#login-mode .on", root).dataset.mode === "sso";
      fields.signInWith = sso ? { provider: val("f-provider"), account: val("f-sso-account"), name: val("f-provider-name") } : null;
    } else if (type === "card") {
      ["cardholder", "expMonth", "expYear", "cvv", "pin", "zip", "cardType"].forEach(set);
      fields.number = val("f-number").replace(/\D/g, "");
      fields.brand = root._brand || "";
    } else if (type === "note") { fields.body = $("#f-body", root).value; }
    else if (type === "identity") { ["fullName", "email", "phone", "birthday", "company", "address1", "address2", "city", "state", "zip", "country"].forEach(set); }
    else if (type === "alias") { ["alias", "forwardsTo"].forEach(set); }
    if (type !== "note") fields.notes = $("#f-notes", root).value;
    fields.custom = $$(".cf", root).map((r) => ({ label: $(".cf-l", r).value.trim(), value: $(".cf-v", r).value, hidden: $(".cf-h", r).checked })).filter((c) => c.label || c.value);
    const payload = {
      type, title: val("f-title") || (type === "login" ? hostOf(fields.urls?.[0]) : "") || "Untitled", fields,
      vaultId: val("f-vault"), favorite: $("#f-fav", root).checked,
      tags: val("f-tags").split(",").map((t) => t.trim()).filter(Boolean),
    };
    try {
      const saved = item ? await api("PUT", "items/" + item.id, payload) : await POST("items", payload);
      closeModal();
      S.selected = saved.id;
      await reload();
      toast(item ? "Saved" : "Added to your vault");
    } catch (x) { $("#err", root).textContent = x.message; }
  });
}

/* ---------------- generator ---------------- */
function genOpts() {
  return S.gen || (S.gen = JSON.parse(localStorageGet("gen") || "null") || { type: "random", length: 20, upper: true, lower: true, digits: true, symbols: true, avoidAmbiguous: false, words: 5, separator: "-", capitalize: true, number: true });
}
async function renderGenerator(el, intoInput = null) {
  const o = genOpts();
  const history = intoInput ? [] : await GET("generator-history").catch(() => []);
  el.innerHTML = `${intoInput ? "" : `<h1 style="margin-top:0">Password generator</h1><p class="muted">Strong, random passwords and memorable passphrases — made on this computer.</p>`}
    <div class="seg" id="g-type">${[["random", "Random"], ["passphrase", "Passphrase"], ["pin", "PIN"]].map(([k, l]) => `<button type="button" data-t="${k}" class="${o.type === k ? "on" : ""}">${l}</button>`).join("")}</div>
    <div class="genout mono" id="g-out" style="margin-top:14px"></div><div id="g-meter"></div>
    <div class="row" style="margin:12px 0"><button type="button" class="btn primary" id="g-copy">${intoInput ? "Use this password" : "Copy"}</button><button type="button" class="btn" id="g-again">⟳ New</button></div>
    <div class="panel" id="g-opts"></div>
    ${history.length ? `<div class="panel"><h3>Recently generated</h3>${history.slice(0, 10).map((x) => `<div class="field" style="padding:8px 0"><div class="body mono">${pwHTML(x.password)}</div><div class="small muted">${fmtDate(x.createdAt)}</div><button class="btn ghost icon" data-a="copy" data-val="${h(x.password)}" data-what="Password copied">⧉</button></div>`).join("")}</div>` : ""}`;
  const optsHTML = () => o.type === "random" ? `
      <label class="lbl">Length: <b id="g-len-v">${o.length}</b></label><input type="range" min="8" max="64" value="${o.length}" id="g-len">
      ${[["upper", "A–Z uppercase"], ["lower", "a–z lowercase"], ["digits", "0–9 digits"], ["symbols", "!@# symbols"], ["avoidAmbiguous", "Avoid look-alikes (l, 1, O, 0)"]].map(([k, l]) => `<label class="check"><input type="checkbox" data-o="${k}" ${o[k] ? "checked" : ""}> ${l}</label>`).join("")}`
    : o.type === "passphrase" ? `
      <label class="lbl">Words: <b id="g-len-v">${o.words}</b></label><input type="range" min="3" max="10" value="${o.words}" id="g-len">
      <label class="lbl">Separator</label><select class="input" id="g-sep">${[["-", "Hyphen -"], [".", "Period ."], ["_", "Underscore _"], [" ", "Space"], [",", "Comma ,"]].map(([v, l]) => `<option value="${h(v)}" ${o.separator === v ? "selected" : ""}>${l}</option>`).join("")}</select>
      <label class="check"><input type="checkbox" data-o="capitalize" ${o.capitalize ? "checked" : ""}> Capitalize words</label>
      <label class="check"><input type="checkbox" data-o="number" ${o.number ? "checked" : ""}> Include a number</label>`
    : `<label class="lbl">Digits: <b id="g-len-v">${o.pinLength || 6}</b></label><input type="range" min="4" max="12" value="${o.pinLength || 6}" id="g-len">`;
  let current = "";
  const gen = async () => {
    localStorageSet("gen", JSON.stringify(o));
    const r = await POST("generate", { ...o, length: o.type === "pin" ? o.pinLength || 6 : o.length });
    current = r.password;
    $("#g-out", el).innerHTML = pwHTML(current);
    $("#g-meter", el).innerHTML = meterHTML(r.strength);
  };
  const mountOpts = () => {
    $("#g-opts", el).innerHTML = optsHTML();
    $("#g-len", el).addEventListener("input", (e) => {
      const n = +e.target.value;
      if (o.type === "random") o.length = n; else if (o.type === "passphrase") o.words = n; else o.pinLength = n;
      $("#g-len-v", el).textContent = n; gen();
    });
    $$("[data-o]", el).forEach((c) => c.addEventListener("change", () => { o[c.dataset.o] = c.checked; gen(); }));
    $("#g-sep", el)?.addEventListener("change", (e) => { o.separator = e.target.value; gen(); });
  };
  $$("#g-type button", el).forEach((b) => b.addEventListener("click", () => {
    o.type = b.dataset.t; $$("#g-type button", el).forEach((x) => x.classList.toggle("on", x === b)); mountOpts(); gen();
  }));
  $("#g-again", el).addEventListener("click", gen);
  $("#g-copy", el).addEventListener("click", async () => {
    await POST("generator-history", { password: current }).catch(() => {});
    if (intoInput) { intoInput.value = current; intoInput.dispatchEvent(new Event("input")); intoInput.type = "text"; closeGenPopover(); toast("Password set"); }
    else { copy(current, "Password copied"); renderGenerator(el); }
  });
  mountOpts(); gen();
}
function closeGenPopover() { $("#gen-pop")?.remove(); }
function genInto(input) {
  closeGenPopover();
  const pop = document.createElement("div");
  pop.id = "gen-pop";
  pop.className = "backdrop";
  pop.innerHTML = `<div class="modal" style="max-width:480px"><div class="mh"><h3>🎲 Generate password</h3><button type="button" class="btn ghost icon" id="gp-x">✕</button></div><div class="mb" style="padding-top:16px" id="gp"></div></div>`;
  document.body.appendChild(pop);
  $("#gp-x", pop).addEventListener("click", closeGenPopover);
  renderGenerator($("#gp", pop), input);
}

/* ---------------- watchtower ---------------- */
async function renderWatchtower(el) {
  el.innerHTML = `<h1 style="margin-top:0">🛡️ Watchtower</h1><p class="muted">Checking your vault…</p>`;
  const w = (S.watch = await GET("watchtower"));
  const color = w.score >= 80 ? "var(--ok)" : w.score >= 50 ? "var(--warn)" : "var(--bad)";
  const stat = (key, label, desc, cls) => `<div class="stat" data-a="wt-filter" data-k="${key}" data-l="${h(label)}"><div class="n" style="color:${w[key].length ? cls : "var(--ok)"}">${w[key].length}</div><b>${label}</b><div class="small muted">${desc}</div></div>`;
  const breached = S.breach ? Object.keys(S.breach.breached).length : null;
  el.innerHTML = `<h1 style="margin-top:0">🛡️ Watchtower</h1><p class="muted">Your security dashboard. Fix the issues below to raise your score.</p>
    <div class="score"><div class="big" style="color:${color}">${w.score}</div><div><b>${w.score >= 80 ? "Excellent" : w.score >= 50 ? "Could be better" : "Needs attention"}</b><div class="muted">Security score across ${w.total} logins</div></div></div>
    <div class="stats">
      ${stat("weak", "Weak", "Easy to guess", "var(--bad)")}
      ${stat("reused", "Reused", "Same password on several sites", "var(--bad)")}
      ${stat("old", "Old", "Not changed in a year", "var(--warn)")}
      ${stat("missing2fa", "2FA available", "Sites that support 2FA codes", "var(--warn)")}
      ${stat("insecure", "Unsecured websites", "http:// instead of https://", "var(--warn)")}
      ${stat("expiring", "Expiring cards", "Expired or expiring soon", "var(--warn)")}
    </div>
    <div class="panel"><h3>Breached passwords</h3>
      <p class="muted small">Checks your passwords against Have I Been Pwned's list of 900M+ leaked passwords. Only the first 5 characters of each password's SHA-1 hash leave this computer (k-anonymity) — never the password.</p>
      ${breached !== null ? `<p><b style="color:${breached ? "var(--bad)" : "var(--ok)"}">${breached ? `${breached} login${breached > 1 ? "s use" : " uses"} a breached password` : "✓ None of your passwords are in known breaches"}</b> <span class="small muted">· checked ${fmtDate(S.breach.checkedAt)}</span></p>
        ${breached ? `<button class="btn" data-a="bt-filter">Show them</button>` : ""}` : ""}
      <button class="btn primary" data-a="breach-check" style="margin-top:8px">Check for breaches</button></div>`;
}

/* ---------------- settings ---------------- */
async function renderSettings(el) {
  const st = S.server, s = st.settings || {};
  const devices = await GET("devices").catch(() => []);
  el.innerHTML = `<h1 style="margin-top:0">Settings</h1>
  <div class="panel"><h3>Jace account</h3>
    ${st.jace ? `<div class="acct">${avatarHTML(st.jace)}<div class="grow"><b>${h(st.jace.name || st.jace.username)}</b><div class="small muted">@${h(st.jace.username)} · ${st.sync?.status === "synced" ? `Synced ${fmtDate(st.sync.at)}` : st.sync?.status === "error" ? h(st.sync.error) : "Sync on"}</div></div>
      <button class="btn" data-a="sync">Sync now</button><button class="btn danger" data-a="jace-signout">Sign out</button></div>
      <p class="small muted">Your vault is end-to-end encrypted before it's uploaded to Jace. Jace stores only ciphertext and can't read, reset or recover it.</p>`
      : `<p class="muted">Sign in to sync your encrypted vault to all your devices and the browser extension.</p><button class="btn jace-btn" data-a="jace-signin"><img src="/jace-logo.svg" alt="">Sign in with Jace</button>`}
  </div>
  <div class="panel"><h3>Security</h3>
    <label class="lbl">Auto-lock after</label><select class="input" data-s="autoLockMinutes">${[[1, "1 minute"], [5, "5 minutes"], [10, "10 minutes"], [30, "30 minutes"], [60, "1 hour"], [240, "4 hours"], [0, "Never"]].map(([v, l]) => `<option value="${v}" ${+s.autoLockMinutes === v ? "selected" : ""}>${l}</option>`).join("")}</select>
    <label class="lbl">Clear copied items from clipboard after</label><select class="input" data-s="clipboardClearSeconds">${[[15, "15 seconds"], [30, "30 seconds"], [60, "1 minute"], [120, "2 minutes"], [0, "Never"]].map(([v, l]) => `<option value="${v}" ${+s.clipboardClearSeconds === v ? "selected" : ""}>${l}</option>`).join("")}</select>
    ${st.keyMode === "jace" ? `<label class="lbl">Unlock</label>
    <p class="muted small">No master password: this vault unlocks with your Jace account. ⚠ It's encrypted, but not end-to-end: the Jace Passwords server holds the key for your account. Add a master password to make it end-to-end encrypted.</p>
    <button class="btn primary" data-a="change-pw">Add a master password</button>` : `
    <div class="row" style="margin-top:14px;flex-wrap:wrap"><button class="btn" data-a="change-pw">Change master password</button>${st.usesSecretKey ? `<button class="btn" data-a="show-kit">View Emergency Kit</button>` : ""}${st.jace ? `<button class="btn" data-a="use-jace-unlock">Unlock with Jace instead</button>` : ""}</div>
    <label class="lbl">Secret Key</label>
    ${st.usesSecretKey
      ? `<p class="muted small">New devices need your Secret Key as well as your master password.${st.jace ? " Since your vault is linked to Jace, you can stop using it: then signing in with Jace and your master password is enough." : ""}</p>${st.jace ? `<button class="btn" data-a="secret-key" data-use="0">Stop using a Secret Key</button>` : ""}`
      : `<p class="muted small">No Secret Key: on a new device, sign in with Jace and enter your master password. Your Jace sign-in protects the synced copy. For a second secret only your devices know, add a Secret Key.</p><button class="btn" data-a="secret-key" data-use="1">Add a Secret Key</button>`}`}
  </div>
  <div class="panel"><h3>✈ Travel Mode</h3><p class="muted small">Crossing a border? Travel Mode hides every vault not marked “safe for travel” from this device and the extension until you turn it off.</p>
    <label class="check"><input type="checkbox" data-s="travelMode" ${s.travelMode ? "checked" : ""}> Travel Mode is on</label></div>
  <div class="panel"><h3>Vaults</h3>${S.data.vaults.map((v) => `<div class="field" style="padding:8px 0"><span class="dot" style="width:12px;height:12px;border-radius:4px;background:${h(v.color)}"></span><div class="body">${h(v.icon)} <b>${h(v.name)}</b> ${v.travelSafe ? `<span class="pill ok">Safe for travel</span>` : ""}</div><button class="btn small" data-a="edit-vault" data-id="${h(v.id)}">Edit</button></div>`).join("")}
    <button class="btn" data-a="new-vault" style="margin-top:8px">＋ New vault</button></div>
  ${st.web ? `<div class="panel"><h3>🧩 Autofill and passkeys</h3><p class="muted small">You're using Jace Passwords on the web. For autofill and passkeys in your browser, get the <a href="https://github.com/okjace/jace-passwords/releases/latest" target="_blank" rel="noopener">desktop app and extension</a>, and sign in with the same Jace account: they open this same vault.</p></div>` : ""}
  <div class="panel ${st.web ? "hidden" : ""}"><h3>🧩 Browser extension (autofill)</h3>
    <p class="muted small">Get the extension from the <a href="https://github.com/okjace/jace-passwords/releases/latest" target="_blank" rel="noopener">latest release</a>: in Jace Browser or Firefox, install the signed <code>.xpi</code> (about:addons → gear → Install Add-on From File). In Chrome, Edge or Brave, unzip the <code>-chrome.zip</code> and load it at chrome://extensions → Developer mode → Load unpacked. Then pair it with this code:</p>
    <div id="pair-out"></div><button class="btn primary" data-a="pair">Get pairing code</button>
    ${devices.length ? `<label class="lbl">Paired browsers</label>${devices.map((d) => `<div class="field" style="padding:8px 0"><div class="body"><b>${h(d.name)}</b><div class="small muted">Paired ${fmtDate(d.createdAt)}</div></div><button class="btn danger small" data-a="unpair" data-id="${h(d.id)}">Remove</button></div>`).join("")}` : ""}
  </div>
  <div class="panel"><h3>📧 Email aliases</h3><p class="muted small">Your real address that aliases forward to.</p>
    <input class="input" type="email" data-s="aliasBase" value="${h(s.aliasBase || "")}" placeholder="you@gmail.com"></div>
  <div class="panel"><h3>Appearance</h3><div class="seg" id="theme">${["system", "light", "dark"].map((t) => `<button data-a="theme" data-t="${t}" class="${(s.theme || "system") === t ? "on" : ""}">${t[0].toUpperCase() + t.slice(1)}</button>`).join("")}</div></div>
  <div class="panel"><h3>Import & export</h3>
    <p class="muted small">Import a CSV from Chrome, Firefox, Safari, Edge, 1Password, Bitwarden, Proton Pass, LastPass or Dashlane.</p>
    <label class="btn">📥 Import CSV<input type="file" accept=".csv,text/csv" id="imp" hidden></label>
    <button class="btn" data-a="export" data-f="json">📦 Encrypted backup</button><button class="btn" data-a="export" data-f="csv">📄 Export CSV (unencrypted)</button></div>
  <p class="small muted">Jace Passwords ${h(st.version)} · AES-256-GCM · ${st.keyMode === "jace" ? "unlocked with Jace" : st.usesSecretKey ? "scrypt + Secret Key" : "scrypt"}</p>`;
  $$("[data-s]", el).forEach((c) => c.addEventListener("change", async () => {
    const v = c.type === "checkbox" ? c.checked : c.tagName === "SELECT" ? +c.value : c.value.trim();
    await api("PUT", "settings", { [c.dataset.s]: v });
    await reload(); toast("Saved");
  }));
  $("#imp", el).addEventListener("change", async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const r = await POST("import", { csv: await file.text(), vaultId: S.data.vaults[0].id }).catch((x) => toast(x.message));
    if (r) { await reload(); toast(`Imported ${r.imported} items`); }
  });
}

function passwordPrompt(title, desc, cb) {
  if (S.server?.keyMode === "jace") return cb("").catch((x) => toast(x.message)); // no master password to ask for
  modal(`<form class="modal" style="max-width:420px" id="pp"><div class="mh"><h3>${h(title)}</h3><button type="button" class="btn ghost icon" data-a="close">✕</button></div>
    <div class="mb"><p class="muted">${h(desc)}</p><input class="input" type="password" id="pp-pw" placeholder="Master password" autocomplete="current-password"><div class="error" id="err"></div></div>
    <div class="mf"><button type="button" class="btn" data-a="close">Cancel</button><button class="btn primary">Continue</button></div></form>`, (root) => {
    $("#pp", root).addEventListener("submit", async (e) => {
      e.preventDefault();
      try { await cb($("#pp-pw", root).value); } catch (x) { $("#err", root).textContent = x.message; }
    });
  });
}

function download(name, content, mime) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([content], { type: mime }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

function editVault(v) {
  const icons = ["🔐", "🏠", "💼", "👪", "💰", "🎮", "🛒", "🧪", "✈️", "🗂️"];
  const colors = ["#3ddc84", "#3b82f6", "#a78bfa", "#f59e0b", "#ef4444", "#ec4899", "#14b8a6", "#8b919c"];
  modal(`<form class="modal" style="max-width:440px" id="fv"><div class="mh"><h3>${v ? "Edit vault" : "New vault"}</h3><button type="button" class="btn ghost icon" data-a="close">✕</button></div>
    <div class="mb">${inp("v-name", "Name", v?.name || "", "required")}
      <label class="lbl">Icon</label><div class="row" style="flex-wrap:wrap">${icons.map((i) => `<label class="btn icon"><input type="radio" name="vi" value="${i}" ${(v?.icon || "🗂️") === i ? "checked" : ""} hidden>${i}</label>`).join("")}</div>
      <label class="lbl">Color</label><div class="row">${colors.map((c) => `<label><input type="radio" name="vc" value="${c}" ${(v?.color || colors[0]) === c ? "checked" : ""}><span class="dot" style="display:inline-block;width:18px;height:18px;border-radius:6px;background:${c}"></span></label>`).join("")}</div>
      <label class="check"><input type="checkbox" id="v-travel" ${v?.travelSafe ? "checked" : ""}> ✈ Safe for travel (stays visible in Travel Mode)</label><div class="error" id="err"></div></div>
    <div class="mf">${v ? `<button type="button" class="btn danger" data-a="del-vault" data-id="${h(v.id)}" style="margin-right:auto">Delete</button>` : ""}<button type="button" class="btn" data-a="close">Cancel</button><button class="btn primary">Save</button></div></form>`, (root) => {
    $("#fv", root).addEventListener("submit", async (e) => {
      e.preventDefault();
      const body = { name: $("#v-name", root).value, icon: $("[name=vi]:checked", root)?.value, color: $("[name=vc]:checked", root)?.value, travelSafe: $("#v-travel", root).checked };
      try { const r = v ? await api("PUT", "vaults/" + v.id, body) : await POST("vaults", body); closeModal(); if (!v) S.view = "vault:" + r.id; await reload(); }
      catch (x) { $("#err", root).textContent = x.message; }
    });
  });
}

function palette() {
  modal(`<div class="modal palette"><input class="input" id="pal" placeholder="Search your vault…" autocomplete="off"><div class="res" id="pal-res"></div></div>`, (root) => {
    const run = () => {
      const q = $("#pal", root).value.toLowerCase();
      const res = liveItems().filter((i) => !q || [i.title, i.fields?.username, ...(i.fields?.urls || [])].join(" ").toLowerCase().includes(q)).slice(0, 12);
      $("#pal-res", root).innerHTML = res.map((i, n) => `<div class="li ${n === 0 ? "on" : ""}" data-a="pal-go" data-id="${h(i.id)}">${tileFor(i)}<div class="meta"><div class="t">${h(i.title)}</div><div class="s">${h(subtitle(i))}</div></div>
        ${i.fields?.password ? `<button class="btn ghost small" data-a="copy" data-val="${h(i.fields.password)}" data-what="Password copied">Copy password</button>` : ""}</div>`).join("") || `<div class="empty">No matches</div>`;
    };
    $("#pal", root).addEventListener("input", run);
    $("#pal", root).addEventListener("keydown", (e) => { if (e.key === "Enter") $(".li", root)?.click(); });
    run();
  });
}

/* ---------------- actions ---------------- */
const ACTIONS = {
  async "jace-signin"(el) {
    if (el) { el.disabled = true; }
    const r = await POST("jace/signin").finally(() => el && (el.disabled = false));
    if (r.signedIn) { toast("Signed in with this computer's Jace account"); if (S.onboard) S.onboard.remote = undefined; return refreshState(); }
    if (/QtWebEngine/.test(navigator.userAgent)) toast("Finish signing in to Jace in your browser…");
    location.href = r.url;
  },
  async "jace-signout"() { if (!confirm("Sign out of Jace? Your vault stays on this computer; sync stops.")) return; await POST("jace/signout"); if (S.onboard) S.onboard.remote = undefined; await refreshState(); },
  "ob-create"() { S.onboard.step = "create"; render(); },
  "ob-restore"() { S.onboard.step = "restore"; render(); },
  "ob-back"() { S.onboard.step = "welcome"; render(); },
  "kit-copy"(el) { copy(el.dataset.sk, "Secret Key copied"); },
  print() { window.print(); },
  async "kit-done"() { S.onboard = null; await refreshState(); toast("Your vault is ready 🎉"); },
  async lock() { await POST("lock"); S.data = null; await refreshState(); },
  async sync() { toast("Syncing…"); const r = await POST("sync"); S.server.sync = r; await reload(); toast(r.status === "error" ? r.error : "Synced with Jace"); },
  nav(el) { S.view = el.dataset.v; S.selected = null; S.filterIds = null; S.search = ""; render(); },
  tag(el) { S.tag = S.tag === el.dataset.t ? null : el.dataset.t; if (["generator", "watchtower", "settings"].includes(S.view)) S.view = "all"; render(); },
  "clear-filter"() { S.filterIds = null; render(); },
  select(el) { S.selected = el.dataset.id; renderMain($("#app")); },
  deselect() { S.selected = null; renderMain($("#app")); },
  new() { pickType(); },
  "new-type"(el) { editItem(null, el.dataset.type); },
  edit(el) { editItem(S.data.items.find((i) => i.id === el.dataset.id)); },
  async fav(el) { const i = S.data.items.find((x) => x.id === el.dataset.id); await api("PUT", "items/" + i.id, { favorite: !i.favorite }); await reload(); },
  async trash(el) { await api("DELETE", "items/" + el.dataset.id); S.selected = null; await reload(); toast("Moved to Trash"); },
  async restore(el) { await POST("items/" + el.dataset.id + "/restore"); await reload(); toast("Restored"); },
  async purge(el) { if (!confirm("Delete this item forever? This can't be undone.")) return; await api("DELETE", "items/" + el.dataset.id + "?purge=1"); S.selected = null; await reload(); },
  async "empty-trash"() { if (!confirm("Delete everything in Trash forever? This can't be undone.")) return; await api("DELETE", "trash"); await reload(); },
  reveal(el) { const k = el.dataset.k; S.revealed.has(k) ? S.revealed.delete(k) : S.revealed.add(k); if (k.endsWith(":Card number")) S.revealed.has(k) ? S.revealed.add(k.split(":")[0] + ":num") : S.revealed.delete(k.split(":")[0] + ":num"); renderMain($("#app")); },
  copy(el) { copy(el.dataset.val, el.dataset.what || "Copied"); },
  "copy-totp"(el) { const c = S.codes[el.dataset.id]; if (c) copy(c.code, "2FA code copied"); },
  close() { closeModal(); },
  "modal-bg"(el, e) { if (e.target === el) closeModal(); },
  "toggle-pw"() { const p = $("#f-password"); p.type = p.type === "password" ? "text" : "password"; },
  "gen-into"() { genInto($("#f-password")); },
  "add-url"() { $("#urls").insertAdjacentHTML("beforeend", `<input class="input url-in" style="margin-bottom:6px" placeholder="https://example.com">`); $$(".url-in").at(-1).focus(); },
  "add-custom"() { $("#customs").insertAdjacentHTML("beforeend", customRow()); },
  "rm-custom"(el) { el.closest(".cf").remove(); },
  async "make-alias"() {
    const site = $(".url-in")?.value ? hostOf($(".url-in").value).split(".").slice(-2, -1)[0] : $("#f-title")?.value;
    try {
      const r = await POST("alias", { site, base: $("#f-forwardsTo")?.value });
      const target = $("#f-alias") || $("#f-username");
      target.value = r.alias;
      if ($("#f-forwardsTo")) $("#f-forwardsTo").value = r.forwardsTo;
      toast("Alias created");
    } catch (x) { toast(x.message); }
  },
  async "del-passkey"(el) {
    if (!confirm("Delete this passkey? You won't be able to sign in with it any more — add another sign-in method on the site first.")) return;
    const i = S.data.items.find((x) => x.id === el.dataset.id);
    await api("PUT", "items/" + i.id, { fields: { ...i.fields, passkeys: i.fields.passkeys.filter((p) => p.credentialId !== el.dataset.cred) } });
    await reload(); toast("Passkey deleted");
  },
  "new-vault"() { editVault(null); },
  "edit-vault"(el) { editVault(S.data.vaults.find((v) => v.id === el.dataset.id)); },
  async "del-vault"(el) { if (!confirm("Delete this vault? Its items move to Trash.")) return; try { await api("DELETE", "vaults/" + el.dataset.id); closeModal(); S.view = "all"; await reload(); } catch (x) { toast(x.message); } },
  "wt-filter"(el) { S.filterIds = { ids: S.watch[el.dataset.k], label: el.dataset.l }; S.view = "all"; S.selected = null; render(); },
  "bt-filter"() { S.filterIds = { ids: Object.keys(S.breach.breached), label: "Breached" }; S.view = "all"; render(); },
  async "breach-check"(el) { el.disabled = true; el.textContent = "Checking…"; try { S.breach = await POST("watchtower/breach"); } catch (x) { toast(x.message); } renderWatchtower($("#page")); },
  async pair() {
    const r = await POST("pair");
    $("#pair-out").innerHTML = `<div class="genout mono" style="text-align:center;letter-spacing:.3em;font-size:32px;margin:10px 0">${h(r.code)}</div><p class="small muted">Type this in the extension within 5 minutes.</p>`;
  },
  async unpair(el) { await api("DELETE", "devices/" + el.dataset.id); render(); },
  async theme(el) { localStorageSet("theme", el.dataset.t); await api("PUT", "settings", { theme: el.dataset.t }); await reload(); },
  "change-pw"() {
    const adding = S.server?.keyMode === "jace";
    modal(`<form class="modal" style="max-width:440px" id="cp"><div class="mh"><h3>${adding ? "Add a master password" : "Change master password"}</h3><button type="button" class="btn ghost icon" data-a="close">✕</button></div>
      <div class="mb">${adding ? `<p class="muted small">Your vault becomes end-to-end encrypted: only this password opens it, and nobody can reset it for you.</p>` : inp("cp-cur", "Current master password", "", 'type="password" autocomplete="current-password"')}${inp("cp-new", "New master password", "", 'type="password" autocomplete="new-password"')}<div id="cp-m"></div>${inp("cp-new2", "Confirm new password", "", 'type="password" autocomplete="new-password"')}<div class="error" id="err"></div></div>
      <div class="mf"><button type="button" class="btn" data-a="close">Cancel</button><button class="btn primary">Change password</button></div></form>`, (root) => {
      $("#cp-new", root).addEventListener("input", async (e) => ($("#cp-m", root).innerHTML = meterHTML(await POST("strength", { password: e.target.value }))));
      $("#cp", root).addEventListener("submit", async (e) => {
        e.preventDefault();
        if ($("#cp-new", root).value !== $("#cp-new2", root).value) return ($("#err", root).textContent = "The new passwords don't match.");
        try { await POST("password", { current: $("#cp-cur", root)?.value || "", new: $("#cp-new", root).value }); closeModal(); await reload(); toast(adding ? "Master password added: your vault is end-to-end encrypted" : "Master password changed"); }
        catch (x) { $("#err", root).textContent = x.message; }
      });
    });
  },
  "use-jace-unlock"() {
    if (!confirm("Unlock with your Jace account instead of a master password?\n\nYour vault stays encrypted, but no longer end-to-end: the Jace Passwords server will hold the key for your account, so whoever controls it, or gets into your Jace account, could open your vault.")) return;
    passwordPrompt("Unlock with Jace instead", "Enter your current master password to switch.", async (pw) => {
      await POST("key-mode", { mode: "jace", current: pw });
      closeModal(); await reload(); toast("Your vault now unlocks with your Jace account");
    });
  },
  "secret-key"(el) {
    const use = el.dataset.use === "1";
    passwordPrompt(use ? "Add a Secret Key" : "Stop using a Secret Key",
      use ? "You'll get a Secret Key to save. New devices will need it along with your master password."
          : "New devices will only need your Jace sign-in and master password. Your Secret Key stops working.",
      async (pw) => {
        const r = await POST("secret-key", { password: pw, use });
        closeModal(); await reload();
        if (r.secretKey) { modal(`<div class="modal"><div class="mh"><h3>Save your Secret Key</h3><button class="btn ghost icon" data-a="close">✕</button></div><div class="mb">
          <div class="kit"><label class="lbl">Secret Key</label><div class="sk mono">${h(r.secretKey)}</div></div>
          <div class="row"><button class="btn" data-a="kit-copy" data-sk="${h(r.secretKey)}">Copy Secret Key</button><button class="btn" data-a="print">Print</button></div></div></div>`); }
        else toast("Secret Key removed");
      });
  },
  "show-kit"() {
    passwordPrompt("Emergency Kit", "Enter your master password to see your Secret Key.", async (pw) => {
      const r = await POST("emergency-kit", { password: pw });
      modal(`<div class="modal"><div class="mh"><h3>Emergency Kit</h3><button class="btn ghost icon" data-a="close">✕</button></div><div class="mb">
        <div class="kit"><div class="logo" style="font-size:16px"><img src="/icon.svg" alt="" style="width:28px;height:28px">Jace Passwords Emergency Kit</div>
        <label class="lbl">Jace account</label><div>${r.account ? "@" + h(r.account.username) : "Not linked"}</div>
        <label class="lbl">Secret Key</label><div class="sk mono">${h(r.secretKey)}</div>
        <label class="lbl">Master password</label><div style="border-bottom:1px solid var(--muted);height:28px"></div></div>
        <div class="row"><button class="btn" data-a="kit-copy" data-sk="${h(r.secretKey)}">Copy Secret Key</button><button class="btn" data-a="print">Print</button></div></div></div>`);
    });
  },
  export(el) {
    const fmt = el.dataset.f;
    passwordPrompt(fmt === "csv" ? "Export CSV" : "Encrypted backup", fmt === "csv" ? "The CSV is NOT encrypted — anyone who opens it can read your passwords. Delete it after you use it." : "The backup is encrypted. You'll need your master password and Secret Key to open it.", async (pw) => {
      const r = await POST("export", { password: pw, format: fmt });
      download(r.filename, r.content, r.mime);
      closeModal();
    });
  },
  "pal-go"(el, e) { if (e.target.closest("[data-a=copy]")) return; closeModal(); S.view = "all"; S.selected = el.dataset.id; S.search = ""; render(); },
};

document.addEventListener("click", async (e) => {
  const el = e.target.closest("[data-a]");
  if (!el) return;
  const fn = ACTIONS[el.dataset.a];
  if (!fn) return;
  if (el.tagName === "A") return;
  try { await fn(el, e); } catch (x) { if (x.message !== "Locked") toast(x.message); }
});

document.addEventListener("keydown", (e) => {
  const mod = e.ctrlKey || e.metaKey;
  if (!S.data) return;
  if (e.key === "Escape") { if ($("#gen-pop")) closeGenPopover(); else closeModal(); }
  if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); palette(); }
  if (mod && e.key.toLowerCase() === "l") { e.preventDefault(); ACTIONS.lock(); }
  if (mod && e.key.toLowerCase() === "n") { e.preventDefault(); pickType(); }
  if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); $("#search")?.focus(); }
});

// Real activity keeps the vault unlocked; background polling doesn't.
let lastPing = 0;
["pointerdown", "keydown"].forEach((t) => document.addEventListener(t, () => {
  if (S.data && Date.now() - lastPing > 30000) { lastPing = Date.now(); POST("ping").catch(() => {}); }
}, { passive: true }));

// Notice auto-lock, sync and Jace sign-in changes.
setInterval(async () => {
  try {
    const st = await GET("state", true);
    const lockedChanged = st.locked !== S.server?.locked || st.setup !== S.server?.setup
      || (st.jace?.id || null) !== (S.server?.jace?.id || null);
    if ((st.jace?.id || null) !== (S.server?.jace?.id || null) && S.onboard) S.onboard.remote = undefined;
    const syncChanged = st.sync?.version !== S.server?.sync?.version;
    S.server = { ...st };
    if (lockedChanged) { closeModal(); await refreshState(); }
    else if (syncChanged && S.data && !$("#modal-root").innerHTML) await reload();
  } catch { /* server gone */ }
}, 5000);

refreshState().catch((e) => { $("#app").innerHTML = `<div class="center"><div class="card">${LOGO}<p class="error">${h(e.message)}</p></div></div>`; });
