/* Jace Passwords extension.
 * Two ways to work:
 *   desktop     paired with the Jace Passwords app on this computer (it holds the vault)
 *   standalone  on its own: the vault engine (vault/webvault.js, the same as the web app's) runs
 *               here, signed in with Jace through the Jace Passwords site, synced through Jace. */
const B = globalThis.browser ?? globalThis.chrome;
const APP = "http://127.0.0.1:47620";
const WEB = "https://jace-passwords.vercel.app";
if (typeof importScripts === "function" && !globalThis.JPCore) importScripts("vault/words.js", "vault/webvault.js", "mailcodes.js");

// ---------- standalone: the vault engine, with extension storage and the extension's own Jace token ----------
let cache = {};
let persisting = Promise.resolve();
const sessionArea = B.storage.session; // memory only, cleared when the browser closes (keeps you unlocked meanwhile)
async function jaceToken() {
  const t = (await B.storage.local.get("jaceToken")).jaceToken;
  return t && (!t.expires || t.expires > Date.now()) ? t.token : null;
}
const engineReady = (async () => {
  cache = (await B.storage.local.get("jpvault")).jpvault || {};
  const engine = JPCore.create({
    extension: true,
    store: {
      get: (k, d = null) => (k in cache ? cache[k] : d),
      set(k, v) {
        if (v === null) delete cache[k]; else cache[k] = v;
        const snapshot = JSON.parse(JSON.stringify(cache));
        persisting = persisting.then(() => B.storage.local.set({ jpvault: snapshot }));
      },
    },
    async jace(method, path, body, headers = {}) {
      const token = await jaceToken();
      if (!token) return { status: 401, body: { error: "signed_out", error_description: "Sign in with Jace first." } };
      const r = await fetch(`${WEB}/api/jace/${path}`, { method,
        headers: { Authorization: "Bearer " + token, "X-Jace-Passwords": "1", ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
        body: body ? JSON.stringify(body) : undefined });
      return { status: r.status, body: await r.json().catch(() => ({})) };
    },
    async signout() { await B.storage.local.remove("jaceToken"); },
  });
  const sess = sessionArea ? (await sessionArea.get("jpSession")).jpSession : null;
  if (sess) await engine.restoreSession(sess);
  return engine;
})();
async function rememberSession(engine) {
  if (sessionArea) await sessionArea.set({ jpSession: engine.exportSession() });
}

async function signInWithJace() {
  const redirect = B.identity.getRedirectURL();
  const final = await B.identity.launchWebAuthFlow({ url: `${WEB}/api/jace/signin?ext_redirect=${encodeURIComponent(redirect)}`, interactive: true });
  const frag = new URLSearchParams(new URL(final).hash.slice(1));
  const token = frag.get("token");
  if (!token) throw new Error(frag.get("error") || "Jace didn't sign you in.");
  await B.storage.local.set({ jaceToken: { token, expires: Date.now() + (+frag.get("expires_in") || 86400) * 1000 } });
  const engine = await engineReady;
  engine.forgetUser();
  await engine.matchAccount(); // a different account: its own vault, not the last one's
  await rememberSession(engine);
  await fetchVault(engine);
  return { ok: true };
}

// The vault on your Jace account, saved here still encrypted, so you can unlock it.
async function fetchVault(engine) {
  if (engine.exists()) return true;
  return engine.fetchRemote().catch(() => false);
}

async function standalone(route, body = {}) {
  const engine = await engineReady;
  try {
    if (route === "status") {
      if (!(await jaceToken())) return { error: "signedout", message: "Sign in with Jace in the Jace Passwords toolbar button." };
      if (!engine.exists() && !(await fetchVault(engine))) return { error: "novault", message: "Create your vault first." };
    }
    const r = await engine.ext(route, body);
    await rememberSession(engine);
    return r;
  } catch (e) {
    await rememberSession(engine);
    if (e.locked) return { error: "locked", message: "Jace Passwords is locked." };
    return { error: "failed", message: e.message || String(e) };
  }
}

const lastFilled = {};   // tabId -> { id, at } so the 2FA field can get the right code
// Kept in session storage too: the browser often stops this background between the login page and
// the 2FA page, which used to forget which login you'd just filled.
async function rememberFilled(tabId, id) {
  lastFilled[tabId] = { id, at: Date.now() };
  if (B.storage.session) await B.storage.session.set({ ["filled:" + tabId]: lastFilled[tabId] });
}
async function recallFilled(tabId) {
  if (lastFilled[tabId]) return lastFilled[tabId];
  if (!B.storage.session) return null;
  return (await B.storage.session.get("filled:" + tabId))["filled:" + tabId] || null;
}
const pendingSave = {};  // tabId -> { url, username, password, at }
const pendingItems = {}; // tabId -> { url, card, identity, at }: details typed into a form, to offer saving

function senderOrigin(sender) {
  if (sender.origin && sender.origin !== "null") return sender.origin;
  try { return new URL(sender.url).origin; } catch { return null; }
}

function b64u(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function token() {
  return (await B.storage.local.get("token")).token || null;
}

async function call(path, method = "GET", body) {
  const t = await token();
  if (!t) { // not paired with the desktop app: standalone
    const [route, qs] = path.split("?");
    return standalone(route, { ...Object.fromEntries(new URLSearchParams(qs || "")), ...(body || {}) });
  }
  let r;
  try {
    r = await fetch(APP + "/ext/" + path, {
      method,
      headers: { ...(t ? { Authorization: "Bearer " + t } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    return { error: "offline", message: "Jace Passwords isn't running. Open the app first." };
  }
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && path !== "pair") return { error: "unpaired", message: j.message };
  if (r.status === 423) return { error: "locked", message: "Jace Passwords is locked." };
  if (!r.ok) return { error: "failed", message: j.message || "Something went wrong." };
  return j;
}

// ---------- sign-in codes from email ----------
// 1. An inbox already open in a tab: content.js reads it.
// 2. Gmail with no tab open: Gmail's own unread-mail feed, with your Gmail sign-in in this browser (needs the
//    optional mail.google.com permission, asked for when you turn Gmail on).
// 3. Outlook / Proton Mail with no tab open (they have no feed): your inbox opens in a background tab for a few
//    seconds, content.js reads it, and the tab closes.
// Only when you open a 2FA field's menu, and only for the email services you turned on. Nothing leaves this browser.
const MAILBOXES = {
  gmail: { name: "Gmail", match: "https://mail.google.com/*", inbox: "https://mail.google.com/mail/u/0/#inbox" },
  outlook: { name: "Outlook", match: "https://outlook.live.com/*", inbox: "https://outlook.live.com/mail/0/" },
  outlookWork: { name: "Outlook (work or school)", match: "https://outlook.office.com/*", inbox: "https://outlook.office.com/mail/" },
  proton: { name: "Proton Mail", match: "https://mail.proton.me/*", inbox: "https://mail.proton.me/u/0/inbox" },
};
const MAIL_HOSTS = { "mail.google.com": "gmail", "outlook.live.com": "outlook", "outlook.office.com": "outlookWork", "outlook.office365.com": "outlookWork", "mail.proton.me": "proton" };
async function mailSources() { return (await B.storage.local.get("mailSources")).mailSources || {}; }
const mailCache = {}; // provider -> { at, codes }
const withTimeout = (p, ms) => Promise.race([Promise.resolve(p).catch(() => null), new Promise((res) => setTimeout(() => res(null), ms))]);
const scanTab = (tabId, siteName) => withTimeout(B.tabs.sendMessage(tabId, { type: "email-codes-scan", siteName }, { frameId: 0 }), 800);

async function gmailFeed(siteName) {
  if (!(await B.permissions.contains({ origins: [MAILBOXES.gmail.match] }).catch(() => false))) return null;
  const r = await withTimeout(fetch("https://mail.google.com/mail/u/0/feed/atom", { credentials: "include", cache: "no-store" }), 8000);
  if (!r || !r.ok) return null;
  const xml = await r.text();
  if (!xml.includes("<feed")) return null; // signed out: Gmail sends a sign-in page instead
  const unxml = (s) => String(s || "").replace(/<!\[CDATA\[|\]\]>/g, "").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&amp;/g, "&");
  const tag = (e, t) => unxml((e.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`)) || [])[1]);
  const out = [];
  [...xml.matchAll(/<entry>([\s\S]*?)<\/entry>/g)].slice(0, 10).forEach(([, e], n) => {
    const issued = Date.parse(tag(e, "issued") || tag(e, "modified"));
    if (issued && Date.now() - issued > 30 * 60 * 1000) return; // codes are short-lived: last 30 minutes only
    const title = tag(e, "title"), text = `${tag(e, "name")} ${title} ${tag(e, "summary")}`;
    for (const code of JPMail.codesIn(text)) {
      out.push({ code, provider: "Gmail", from: title.slice(0, 70), score: (siteName && text.toLowerCase().includes(siteName) ? 4 : 0) + 2 + (8 - Math.min(n, 8)) / 4 });
    }
  });
  return out;
}

async function backgroundInbox(key, siteName) {
  const tab = await B.tabs.create({ url: MAILBOXES[key].inbox, active: false }).catch(() => null);
  if (!tab) return null;
  try {
    for (let i = 0; i < 20; i++) { // up to ~20 s for the inbox to load
      await new Promise((res) => setTimeout(res, 1000));
      const r = await scanTab(tab.id, siteName);
      if (r && (r.codes.length || (r.rows && i >= 3))) return r.codes; // found one, or the list has loaded
    }
    return [];
  } finally {
    B.tabs.remove(tab.id).catch(() => {});
  }
}

async function emailCodes(siteName, fromTab) {
  const sources = await mailSources();
  const tabs = await B.tabs.query({}).catch(() => []);
  // 1. inboxes already open (any webmail tab answers; others don't)
  const open = (await Promise.all(tabs.filter((t) => t.id !== fromTab && !t.discarded).map((t) => scanTab(t.id, siteName)))).filter((a) => a && a.codes);
  let codes = open.flatMap((a) => a.codes);
  const openHosts = new Set(open.map((a) => MAIL_HOSTS[a.host]).filter(Boolean)); // inboxes that answered
  // 2./3. the services you turned on, without an open tab
  if (!codes.length) {
    const jobs = Object.keys(MAILBOXES).filter((k) => sources[k] && !openHosts.has(k)).map(async (k) => {
      const hit = mailCache[k];
      if (hit && Date.now() - hit.at < 15000) return hit.codes;
      let got = k === "gmail" ? await gmailFeed(siteName) : null;
      if (got === null) got = (await backgroundInbox(k, siteName)) || [];
      mailCache[k] = { at: Date.now(), codes: got };
      return got;
    });
    codes = (await Promise.all(jobs)).flat();
  }
  const checked = open.length + Object.keys(MAILBOXES).filter((k) => sources[k]).length;
  return { codes: codes.sort((a, b) => b.score - a.score).slice(0, 3), checked };
}

// ---------- field reports: "this is the password field", for everyone ----------
// Everyone's reports (Jace keeps them) are downloaded as one list now and then, so no site you visit is looked
// up. Your own reports apply here right away, even before they're shared.
const FIELD_KINDS = new Set(["username", "password", "new-password", "totp", "cc-number", "cc-name", "cc-csc", "cc-type", "cc-exp",
  "cc-exp-month", "cc-exp-year", "id-email", "id-phone", "id-name", "id-first", "id-middle", "id-last", "id-company", "id-address1",
  "id-address2", "id-address3", "id-city", "id-state", "id-zip", "id-country", "id-birthday", "none"]);
const plainHost = (h) => String(h || "").toLowerCase().replace(/^www\./, "");
let rulesLoading = null;
async function sharedRules() {
  const c = (await B.storage.local.get("fieldRules")).fieldRules;
  if (c && Date.now() - c.at < 6 * 3600 * 1000) return c.rules;
  rulesLoading ||= (async () => {
    try {
      const r = await fetch(`${WEB}/api/jace/field-rules`);
      const j = r.ok ? await r.json() : null;
      if (j && j.rules && typeof j.rules === "object") { await B.storage.local.set({ fieldRules: { at: Date.now(), rules: j.rules } }); return j.rules; }
    } catch { /* offline: use what we have */ }
    return c?.rules || {};
  })().finally(() => { rulesLoading = null; });
  return rulesLoading;
}
async function myRules() { return (await B.storage.local.get("myFieldRules")).myFieldRules || {}; }

async function reportField(msg) {
  const host = plainHost(msg.host), field = String(msg.field || "").slice(0, 126), kind = String(msg.kind || "");
  if (!host || !/^(name|id|ac|ph|label):./.test(field) || !FIELD_KINDS.has(kind)) return { error: "invalid", message: "That field can't be reported." };
  const mine = await myRules();
  (mine[host] ||= {})[field] = kind;
  await B.storage.local.set({ myFieldRules: mine });
  const body = { host, field, kind };
  try {
    if (await token()) { // connected to the desktop app: it shares it with its Jace sign-in
      const r = await call("field-report", "POST", body);
      return r.error ? { saved: true, shared: false, message: r.message } : { saved: true, shared: true, applied: !!r.applied };
    }
    const t = await jaceToken();
    if (!t) return { saved: true, shared: false, message: "Saved for you. Sign in with Jace to share it with everyone." };
    const r = await fetch(`${WEB}/api/jace/field-rules`, { method: "POST",
      headers: { Authorization: "Bearer " + t, "X-Jace-Passwords": "1", "Content-Type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return { saved: true, shared: false, message: j.error_description || "Saved for you; sharing it didn't work." };
    await B.storage.local.remove("fieldRules"); // fetch the list again next time
    return { saved: true, shared: true, applied: !!j.applied };
  } catch { return { saved: true, shared: false, message: "Saved for you; you're offline, so it isn't shared yet." }; }
}

async function handle(msg, sender) {
  const tabId = sender.tab?.id ?? msg.tabId;
  switch (msg.type) {
    case "status": return call("status");
    case "pair": {
      const r = await call("pair", "POST", { code: msg.code, name: msg.name });
      if (r.token) await B.storage.local.set({ token: r.token });
      return r;
    }
    case "unpair": await B.storage.local.remove("token"); return { ok: true };
    case "mode": return { mode: (await token()) ? "desktop" : "standalone", signedIn: !!(await jaceToken()) };
    case "jace-signin":
      if (sender.tab) return { error: "forbidden" };
      try { return await signInWithJace(); } catch (e) { return { error: "failed", message: e.message || String(e) }; }
    case "jace-signout": {
      if (sender.tab) return { error: "forbidden" };
      const engine = await engineReady;
      engine.lock(); await rememberSession(engine);
      await B.storage.local.remove("jaceToken"); engine.forgetUser();
      return { ok: true };
    }
    case "standalone-unlock": {
      if (sender.tab) return { error: "forbidden" };
      const engine = await engineReady;
      try { await engine.api("POST", "unlock", { password: msg.password || "", secretKey: msg.secretKey || null }); await rememberSession(engine); return { ok: true }; }
      catch (e) { return { error: "failed", message: e.message || String(e) }; }
    }
    case "standalone-remember": { // keep the master password on this browser (engine "remember")
      if (sender.tab) return { error: "forbidden" };
      const engine = await engineReady;
      try { return await engine.api("POST", "remember", { on: !!msg.on, password: msg.password || "" }); }
      catch (e) { return { error: "failed", message: e.message || String(e) }; }
    }
    case "standalone-info": {
      const engine = await engineReady;
      const st = await engine.api("GET", "state").catch(() => ({}));
      return { keyMode: st.keyMode, remembered: st.remembered, needsSecretKey: st.needsSecretKey, jace: st.jace };
    }
    case "open-web": B.tabs.create({ url: WEB + "/app" }); return { ok: true };
    case "latest-version": {
      try { return await (await fetch(`${WEB}/api/jace/ext-latest`)).json(); } catch { return {}; }
    }
    case "unlock": return call("unlock", "POST", { password: msg.password });
    case "lock": return call("lock", "POST", {});
    case "match": return call("match?url=" + encodeURIComponent(msg.url));
    case "search": return call("search?q=" + encodeURIComponent(msg.q || ""));
    case "generate": return call("generate", "POST", msg.opts || {});
    case "fill": {
      const r = await call("fill", "POST", { id: msg.id });
      if (!r.error && r.type === "login" && tabId !== undefined) await rememberFilled(tabId, msg.id);
      return r;
    }
    case "email-codes": { // sign-in codes from your email (see "sign-in codes from email" below)
      if (!sender.tab) return { codes: [] };
      let host = "";
      try { host = new URL(sender.tab.url || sender.url || "").hostname; } catch { /* */ }
      return emailCodes(JPMail.siteName(host), sender.tab.id);
    }
    case "mail-settings": {
      if (sender.tab) return { error: "forbidden" };
      if (msg.set) await B.storage.local.set({ mailSources: { ...(await mailSources()), ...msg.set } });
      const has = await B.permissions.contains({ origins: [MAILBOXES.gmail.match] }).catch(() => false);
      return { sources: await mailSources(), gmailFeed: has };
    }
    case "field-rules-for": { // the rules for the page's site: everyone's, and yours (which win)
      const host = plainHost(msg.host);
      return { shared: (await sharedRules())[host] || {}, mine: (await myRules())[host] || {} };
    }
    case "field-report": return reportField(msg);
    case "totp-for-tab": {
      const lf = await recallFilled(tabId);
      if (!lf || Date.now() - lf.at > 10 * 60 * 1000) return { error: "none" };
      return call("fill", "POST", { id: lf.id });
    }
    case "submitted":
      pendingSave[tabId] = { url: msg.url, username: msg.username, password: msg.password, at: Date.now() };
      return { ok: true };
    case "pending-save": {
      const p = pendingSave[tabId];
      if (!p || Date.now() - p.at > 60 * 1000) return { none: true };
      const check = await call("save-check", "POST", p);
      if (check.error || check.status === "unchanged") { delete pendingSave[tabId]; return { none: true }; }
      return { ...check, username: p.username };
    }
    case "save-pending": {
      const p = pendingSave[tabId];
      delete pendingSave[tabId];
      if (!p || !msg.save) return { ok: true };
      return call("save", "POST", p);
    }
    case "submitted-items":
      pendingItems[tabId] = { url: msg.url, card: msg.card, identity: msg.identity, at: Date.now() };
      return { ok: true };
    case "pending-item": {
      const p = pendingItems[tabId];
      if (!p || Date.now() - p.at > 2 * 60 * 1000) return {};
      for (const type of ["card", "identity"]) {
        if (!p[type]) continue;
        const check = await call("save-check-item", "POST", { type, fields: p[type] });
        if (check.error || check.status === "unchanged") { delete p[type]; continue; }
        return { type, status: check.status, title: check.title, summary: check.summary };
      }
      delete pendingItems[tabId];
      return {};
    }
    case "save-item-pending": {
      const p = pendingItems[tabId];
      if (!p || !p[msg.itemType]) return { ok: true };
      const fields = p[msg.itemType];
      delete p[msg.itemType];
      if (!msg.save) return { ok: true };
      return call("save-item", "POST", { type: msg.itemType, fields });
    }
    case "never-save": {
      delete pendingSave[tabId];
      const never = (await B.storage.local.get("never")).never || [];
      if (!never.includes(msg.site)) never.push(msg.site);
      await B.storage.local.set({ never });
      return { ok: true };
    }
    case "is-never": {
      const never = (await B.storage.local.get("never")).never || [];
      return { never: never.includes(msg.site) };
    }
    case "fill-frames": { // card/address fill for every frame of the tab (each frame decides if it may fill)
      if (!sender.tab) return { error: "forbidden" };
      let topOrigin = "";
      try { topOrigin = new URL(sender.tab.url).origin; } catch { /* */ }
      await B.tabs.sendMessage(sender.tab.id, { type: "do-fill", data: msg.data, nonce: msg.nonce, topOrigin }).catch(() => {});
      return { ok: true };
    }
    case "fill-in-tab": {
      // from the popup: ask the page to fill
      const data = await handle({ type: "fill", id: msg.id, tabId: msg.tabId }, {});
      if (data.error) return data;
      // Every frame gets it, but only the page's own site fills (and payment providers, for cards/addresses).
      let topOrigin = "";
      try { topOrigin = new URL((await B.tabs.get(msg.tabId)).url).origin; } catch { /* */ }
      await B.tabs.sendMessage(msg.tabId, { type: "do-fill", data, nonce: "popup-" + Date.now(), topOrigin }).catch(() => {});
      return { ok: true };
    }
    case "open-app": B.tabs.create({ url: APP + "/" }); return { ok: true };
    case "passkey-list": case "passkey-create": case "passkey-get": {
      // The origin comes from the browser (who sent this), never from the page.
      const origin = senderOrigin(sender);
      if (!origin) return { error: "failed", message: "SecurityError: Unknown page." };
      const req = msg.req || {};
      const rpId = String(msg.type === "passkey-create" ? req.rp?.id : req.rpId || "").toLowerCase();
      if (msg.type === "passkey-list") return call("passkey/list", "POST", { rpId, origin, allow: req.allow || [] });
      const clientData = JSON.stringify({
        type: msg.type === "passkey-create" ? "webauthn.create" : "webauthn.get",
        challenge: String(req.challenge || ""),
        origin,
        crossOrigin: !!sender.frameId,
      });
      const clientDataJSON = b64u(new TextEncoder().encode(clientData));
      if (msg.type === "passkey-create") {
        return call("passkey/create", "POST", { rpId, origin, clientDataJSON, rpName: req.rp?.name || "", user: req.user,
          algs: req.algs || [], exclude: req.exclude || [] });
      }
      return call("passkey/get", "POST", { rpId, origin, clientDataJSON, credentialId: msg.credentialId });
    }
  }
  return { error: "unknown" };
}

B.runtime.onMessage.addListener((msg, sender, reply) => {
  handle(msg, sender).then(reply, (e) => reply({ error: "failed", message: String(e) }));
  return true;
});

B.tabs.onRemoved.addListener((id) => { delete lastFilled[id]; delete pendingSave[id]; delete pendingItems[id]; });

B.runtime.onInstalled.addListener(() => {
  B.contextMenus.create({ id: "jp-generate", title: "Generate a strong password", contexts: ["editable"] });
  B.contextMenus.create({ id: "jp-fill", title: "Fill login from Jace Passwords", contexts: ["editable"] });
  B.contextMenus.create({ id: "jp-report", title: "What is this field? (tell Jace Passwords)", contexts: ["editable"] });
});

B.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "jp-generate") {
    const r = await call("generate", "POST", {});
    if (r.password) B.tabs.sendMessage(tab.id, { type: "insert-generated", password: r.password }, { frameId: info.frameId });
  } else if (info.menuItemId === "jp-report") {
    B.tabs.sendMessage(tab.id, { type: "report-field" }, { frameId: info.frameId });
  } else if (info.menuItemId === "jp-fill") {
    B.tabs.sendMessage(tab.id, { type: "open-menu" }, { frameId: info.frameId });
  }
});

B.commands?.onCommand.addListener(async (cmd, tab) => {
  if (cmd !== "fill-login") return;
  tab = tab || (await B.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab) return;
  const m = await call("match?url=" + encodeURIComponent(tab.url));
  if (m.logins?.length) {
    const data = await handle({ type: "fill", id: m.logins[0].id, tabId: tab.id }, {});
    if (!data.error) B.tabs.sendMessage(tab.id, { type: "do-fill", data });
  }
});
