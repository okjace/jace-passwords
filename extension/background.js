/* Jace Passwords extension — talks to the Jace Passwords app on this computer. */
const B = globalThis.browser ?? globalThis.chrome;
const APP = "http://127.0.0.1:47620";

const lastFilled = {};   // tabId -> { id, site } so the 2FA field can get the right code
const pendingSave = {};  // tabId -> { url, username, password, at }

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
    case "unlock": return call("unlock", "POST", { password: msg.password });
    case "lock": return call("lock", "POST", {});
    case "match": return call("match?url=" + encodeURIComponent(msg.url));
    case "search": return call("search?q=" + encodeURIComponent(msg.q || ""));
    case "generate": return call("generate", "POST", msg.opts || {});
    case "fill": {
      const r = await call("fill", "POST", { id: msg.id });
      if (!r.error && r.type === "login" && tabId !== undefined) lastFilled[tabId] = { id: msg.id, at: Date.now() };
      return r;
    }
    case "totp-for-tab": {
      const lf = lastFilled[tabId];
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
    case "fill-in-tab": {
      // from the popup: ask the page to fill
      const data = await handle({ type: "fill", id: msg.id, tabId: msg.tabId }, {});
      if (data.error) return data;
      await B.tabs.sendMessage(msg.tabId, { type: "do-fill", data }).catch(() => {});
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

B.tabs.onRemoved.addListener((id) => { delete lastFilled[id]; delete pendingSave[id]; });

B.runtime.onInstalled.addListener(() => {
  B.contextMenus.create({ id: "jp-generate", title: "Generate a strong password", contexts: ["editable"] });
  B.contextMenus.create({ id: "jp-fill", title: "Fill login from Jace Passwords", contexts: ["editable"] });
});

B.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "jp-generate") {
    const r = await call("generate", "POST", {});
    if (r.password) B.tabs.sendMessage(tab.id, { type: "insert-generated", password: r.password }, { frameId: info.frameId });
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
