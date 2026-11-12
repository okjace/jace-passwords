"use strict";
/* Jace Passwords on the web (Vercel). The whole vault runs in your browser: the same
 * format, keys and encryption as the desktop app (jace_passwords/crypto.py, vault.py), so
 * both open the vault you sync through Jace. Your master password and Secret Key never
 * leave this page; the server only relays Jace sign-in and the already-encrypted vault.
 *
 * On the desktop app (http://127.0.0.1:47620) this file does nothing. */
(() => {
  const isWeb = location.protocol === "https:" || /[?&]web=1\b/.test(location.search) || sessionStorage.getItem("jp-web") === "1";
  if (!isWeb) return;
  try { sessionStorage.setItem("jp-web", "1"); } catch { /* private mode */ }

  const D = window.JP_DATA;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const subtle = crypto.subtle;
  const VERSION = "1.0.0";
  const FORMAT = "jace-passwords/1";
  const AAD_KEY = enc.encode("jace-passwords:key"), AAD_DATA = enc.encode("jace-passwords:data");
  const KDF = { name: "scrypt", n: 131072, r: 8, p: 1 };
  const B32 = "ABCDEFGHJKLMNPQRSTVWXYZ23456789";
  const DEFAULT_SETTINGS = { autoLockMinutes: 10, clipboardClearSeconds: 30, travelMode: false, theme: "system", aliasBase: "", lockOnSleep: true };
  const ITEM_TYPES = ["login", "card", "note", "identity", "alias"];

  class ApiError extends Error {}
  class Locked extends Error { constructor() { super("The vault is locked."); this.locked = true; } }

  // ---------- bytes ----------
  const b64e = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
  const randBelow = (n) => { // uniform, like secrets.randbelow
    const lim = Math.floor(0x100000000 / n) * n, buf = new Uint32Array(1);
    for (;;) { crypto.getRandomValues(buf); if (buf[0] < lim) return buf[0] % n; }
  };
  const choice = (arr) => arr[randBelow(arr.length)];
  const nowIso = () => new Date().toISOString();
  const newId = () => crypto.randomUUID().replace(/-/g, "");
  const clone = (o) => JSON.parse(JSON.stringify(o));

  // ---------- scrypt (RFC 7914), checked against Python's hashlib.scrypt ----------
  async function pbkdf2(pw, salt, len) {
    const k = await subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
    return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 1 }, k, len * 8));
  }
  function salsa(B, x) {
    x.set(B);
    for (let i = 0; i < 8; i += 2) {
      let u;
      u = x[0] + x[12]; x[4] ^= (u << 7) | (u >>> 25); u = x[4] + x[0]; x[8] ^= (u << 9) | (u >>> 23);
      u = x[8] + x[4]; x[12] ^= (u << 13) | (u >>> 19); u = x[12] + x[8]; x[0] ^= (u << 18) | (u >>> 14);
      u = x[5] + x[1]; x[9] ^= (u << 7) | (u >>> 25); u = x[9] + x[5]; x[13] ^= (u << 9) | (u >>> 23);
      u = x[13] + x[9]; x[1] ^= (u << 13) | (u >>> 19); u = x[1] + x[13]; x[5] ^= (u << 18) | (u >>> 14);
      u = x[10] + x[6]; x[14] ^= (u << 7) | (u >>> 25); u = x[14] + x[10]; x[2] ^= (u << 9) | (u >>> 23);
      u = x[2] + x[14]; x[6] ^= (u << 13) | (u >>> 19); u = x[6] + x[2]; x[10] ^= (u << 18) | (u >>> 14);
      u = x[15] + x[11]; x[3] ^= (u << 7) | (u >>> 25); u = x[3] + x[15]; x[7] ^= (u << 9) | (u >>> 23);
      u = x[7] + x[3]; x[11] ^= (u << 13) | (u >>> 19); u = x[11] + x[7]; x[15] ^= (u << 18) | (u >>> 14);
      u = x[0] + x[3]; x[1] ^= (u << 7) | (u >>> 25); u = x[1] + x[0]; x[2] ^= (u << 9) | (u >>> 23);
      u = x[2] + x[1]; x[3] ^= (u << 13) | (u >>> 19); u = x[3] + x[2]; x[0] ^= (u << 18) | (u >>> 14);
      u = x[5] + x[4]; x[6] ^= (u << 7) | (u >>> 25); u = x[6] + x[5]; x[7] ^= (u << 9) | (u >>> 23);
      u = x[7] + x[6]; x[4] ^= (u << 13) | (u >>> 19); u = x[4] + x[7]; x[5] ^= (u << 18) | (u >>> 14);
      u = x[10] + x[9]; x[11] ^= (u << 7) | (u >>> 25); u = x[11] + x[10]; x[8] ^= (u << 9) | (u >>> 23);
      u = x[8] + x[11]; x[9] ^= (u << 13) | (u >>> 19); u = x[9] + x[8]; x[10] ^= (u << 18) | (u >>> 14);
      u = x[15] + x[14]; x[12] ^= (u << 7) | (u >>> 25); u = x[12] + x[15]; x[13] ^= (u << 9) | (u >>> 23);
      u = x[13] + x[12]; x[14] ^= (u << 13) | (u >>> 19); u = x[14] + x[13]; x[15] ^= (u << 18) | (u >>> 14);
    }
    for (let i = 0; i < 16; i++) B[i] = (B[i] + x[i]) | 0;
  }
  function blockMix(B, Y, r, X, tmp) {
    X.set(B.subarray((2 * r - 1) * 16, 2 * r * 16));
    for (let i = 0; i < 2 * r; i++) {
      for (let k = 0; k < 16; k++) X[k] ^= B[i * 16 + k];
      salsa(X, tmp);
      Y.set(X, ((i & 1) * r + (i >> 1)) * 16);
    }
    B.set(Y);
  }
  async function scrypt(pw, salt, N, r, p, dkLen) {
    const B = await pbkdf2(pw, salt, p * 128 * r);
    const words = 32 * r;
    const V = new Uint32Array(words * N), Y = new Uint32Array(words), X16 = new Uint32Array(16), tmp = new Uint32Array(16);
    for (let blk = 0; blk < p; blk++) {
      const X = new Uint32Array(B.buffer, blk * 128 * r, words); // little-endian, like every browser
      for (let i = 0; i < N; i++) {
        V.set(X, i * words);
        blockMix(X, Y, r, X16, tmp);
        if ((i & 8191) === 0) await new Promise((res) => setTimeout(res));
      }
      for (let i = 0; i < N; i++) {
        const j = X[(2 * r - 1) * 16] & (N - 1);
        for (let k = 0; k < words; k++) X[k] ^= V[j * words + k];
        blockMix(X, Y, r, X16, tmp);
        if ((i & 8191) === 0) await new Promise((res) => setTimeout(res));
      }
    }
    return pbkdf2(pw, B, dkLen);
  }

  // ---------- vault crypto (crypto.py) ----------
  function newSecretKey() {
    const c = Array.from({ length: 26 }, () => choice(B32)).join("");
    return "J1-" + [c.slice(0, 6), ...[0, 1, 2, 3].map((i) => c.slice(6 + i * 5, 11 + i * 5))].join("-");
  }
  function normalizeSecretKey(sk) {
    let raw = String(sk || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    if (raw.startsWith("J1")) raw = raw.slice(2);
    if (raw.length !== 26 || [...raw].some((c) => !B32.includes(c))) {
      throw new ApiError("That Secret Key doesn't look right. It starts with J1- and has 26 more letters and numbers.");
    }
    return raw;
  }
  async function deriveKek(password, secretKey, salt, kdf) {
    if (kdf.name !== "scrypt") throw new ApiError("Unknown key derivation.");
    const k1 = await scrypt(enc.encode(password), salt, kdf.n, kdf.r, kdf.p, 32);
    const ikm = await subtle.importKey("raw", enc.encode(normalizeSecretKey(secretKey)), "HKDF", false, ["deriveBits"]);
    const k2 = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("jace-passwords secret key v1") }, ikm, 256));
    return k1.map((b, i) => b ^ k2[i]);
  }
  async function aes(keyBytes) { return subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]); }
  async function seal(keyBytes, plain, aad) {
    const iv = rand(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, await aes(keyBytes), plain));
    return { iv: b64e(iv), ct: b64e(ct) };
  }
  async function openSealed(keyBytes, box, aad) {
    try {
      return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: b64d(box.iv), additionalData: aad }, await aes(keyBytes), b64d(box.ct)));
    } catch { throw new ApiError("Wrong master password or Secret Key."); }
  }

  // ---------- storage on this device ----------
  const store = {
    get(k, d = null) { try { const v = localStorage.getItem("jp-" + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { v === null ? localStorage.removeItem("jp-" + k) : localStorage.setItem("jp-" + k, JSON.stringify(v)); } catch { throw new ApiError("This browser won't let Jace Passwords save your vault (private mode?)."); } },
  };
  const device = () => store.get("device", {});
  const updateDevice = (c) => { const d = { ...device(), ...c }; for (const k in c) if (c[k] === null) delete d[k]; store.set("device", d); return d; };

  // ---------- the vault (vault.py) ----------
  const V = { key: null, data: null, meta: {}, lastActivity: Date.now() };
  const exists = () => !!store.get("vault");
  const touch = () => (V.lastActivity = Date.now());
  const settings = () => ({ ...DEFAULT_SETTINGS, ...(V.data?.settings || {}) });
  function require_() { if (!V.data) throw new Locked(); touch(); return V.data; }

  function emptyData() {
    const t = nowIso();
    return { vaults: [{ id: newId(), name: "Personal", icon: "🔐", color: "#3ddc84", travelSafe: true, createdAt: t, updatedAt: t }],
      items: [], settings: { ...DEFAULT_SETTINGS }, generatorHistory: [], createdAt: t };
  }
  async function wrap(password, secretKey, account) {
    const salt = rand(16);
    const kek = await deriveKek(password, secretKey, salt, KDF);
    V.meta = { format: FORMAT, account: account !== undefined ? account : V.meta.account ?? null, kdf: { ...KDF },
      salt: b64e(salt), wrappedKey: await seal(kek, V.key, AAD_KEY), keyChangedAt: nowIso() };
  }
  async function fileDict() {
    require_();
    return { ...V.meta, data: await seal(V.key, enc.encode(JSON.stringify(V.data)), AAD_DATA), updatedAt: nowIso() };
  }
  let saving = Promise.resolve();
  function save() { saving = saving.then(async () => store.set("vault", await fileDict())); return saving; }

  async function unlock(password, secretKey, file) {
    const f = file || store.get("vault");
    if (!f || f.format !== FORMAT) throw new ApiError("This isn't a Jace Passwords vault.");
    const sk = secretKey || device().secretKey;
    if (!sk) throw new ApiError("Enter your Secret Key (it's on your Emergency Kit).");
    const kek = await deriveKek(password, sk, b64d(f.salt), f.kdf);
    const key = await openSealed(kek, f.wrappedKey, AAD_KEY);
    V.data = JSON.parse(dec.decode(await openSealed(key, f.data, AAD_DATA)));
    V.key = key;
    V.meta = Object.fromEntries(Object.entries(f).filter(([k]) => k !== "data" && k !== "updatedAt"));
    if (secretKey) updateDevice({ secretKey });
    if (file) await save();
    touch();
  }
  function lock() { V.key = null; V.data = null; }

  async function verifyPassword(pw) {
    try { const f = store.get("vault"); const kek = await deriveKek(pw, device().secretKey, b64d(f.salt), f.kdf); await openSealed(kek, f.wrappedKey, AAD_KEY); return true; }
    catch { return false; }
  }

  function snapshot() {
    const d = clone(require_());
    if (d.settings?.travelMode) {
      const safe = new Set(d.vaults.filter((v) => v.travelSafe).map((v) => v.id));
      d.vaults = d.vaults.filter((v) => safe.has(v.id));
      d.items = d.items.filter((i) => safe.has(i.vaultId));
    }
    d.items = d.items.filter((i) => !i.purged);
    for (const i of d.items) if (i.fields?.passkeys) i.fields.passkeys = i.fields.passkeys.map(({ privateKey, ...p }) => p);
    return d;
  }
  const visible = (trash = false) => snapshot().items.filter((i) => trash || !i.deletedAt);
  function getItem(id) { const it = require_().items.find((i) => i.id === id && !i.purged); if (!it) throw new ApiError("That item doesn't exist."); return it; }

  function createItem(item) {
    const d = require_();
    if (!ITEM_TYPES.includes(item.type)) throw new ApiError("Unknown item type.");
    const t = nowIso();
    const n = { id: newId(), type: item.type, vaultId: d.vaults.some((v) => v.id === item.vaultId) ? item.vaultId : d.vaults[0].id,
      title: String(item.title || "").trim().slice(0, 200) || "Untitled", favorite: !!item.favorite,
      tags: (item.tags || []).map((x) => String(x).slice(0, 40)).slice(0, 20), fields: item.fields || {},
      passwordHistory: [], createdAt: t, updatedAt: t, passwordChangedAt: t };
    d.items.push(n);
    return n;
  }
  function updateItem(id, changes) {
    const d = require_(), it = getItem(id);
    const oldPw = it.fields?.password;
    if (changes.fields && typeof changes.fields === "object") {
      const stored = Object.fromEntries((it.fields?.passkeys || []).map((p) => [p.credentialId, p]));
      const kept = (changes.fields.passkeys || []).filter((p) => stored[p.credentialId]).map((p) => stored[p.credentialId]);
      changes = { ...changes, fields: { ...changes.fields, passkeys: kept } };
      if (!kept.length) delete changes.fields.passkeys;
    }
    for (const k of ["title", "favorite", "tags", "fields", "vaultId"]) {
      if (!(k in changes)) continue;
      if (k === "vaultId" && !d.vaults.some((v) => v.id === changes[k])) continue;
      it[k] = changes[k];
    }
    const newPw = it.fields?.password;
    if (oldPw && newPw !== oldPw) {
      it.passwordHistory = [{ password: oldPw, changedAt: nowIso() }, ...(it.passwordHistory || [])].slice(0, 20);
      it.passwordChangedAt = nowIso();
    }
    it.updatedAt = nowIso();
    return it;
  }
  function purge(id) {
    const it = getItem(id);
    for (const k of Object.keys(it)) if (!["id", "vaultId", "type"].includes(k)) delete it[k];
    it.purged = true; it.updatedAt = nowIso();
  }

  function mergeRemote(remoteData, remoteFile) {
    const d = require_();
    let changed = false;
    for (const coll of ["items", "vaults"]) {
      const mine = new Map((d[coll] || []).map((x) => [x.id, x]));
      for (const r of remoteData[coll] || []) {
        const m = mine.get(r.id);
        if (!m || (r.updatedAt || "") > (m.updatedAt || "")) { mine.set(r.id, r); changed = true; }
      }
      d[coll] = [...mine.values()];
    }
    if ((remoteData.settings?.updatedAt || "") > (d.settings?.updatedAt || "")) { d.settings = remoteData.settings; changed = true; }
    if ((remoteFile.keyChangedAt || "") > (V.meta.keyChangedAt || "")) {
      for (const k of ["kdf", "salt", "wrappedKey", "keyChangedAt"]) V.meta[k] = remoteFile[k];
      changed = true;
    }
    return changed;
  }

  // ---------- Jace (through this site's /api/jace function) ----------
  const sync = { status: "idle", at: null, error: null, version: device().syncVersion || 0 };
  let jaceUser;
  async function jace(method, path, body, headers = {}) {
    const r = await fetch("/api/jace/" + path, { method, credentials: "same-origin",
      headers: { "X-Jace-Passwords": "1", ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
      body: body ? JSON.stringify(body) : undefined });
    const j = await r.json().catch(() => ({}));
    return { status: r.status, body: j };
  }
  let mePromise = null;
  function me() {
    if (jaceUser !== undefined) return Promise.resolve(jaceUser);
    mePromise ||= jace("GET", "me").catch(() => ({ status: 0 })).then((r) => {
      jaceUser = r.status === 200 ? r.body.user : null;
      mePromise = null;
      return jaceUser;
    });
    return mePromise;
  }
  // Silent sign-in (Jace's prompt=none), once per visit: if you're already signed in to Jace
  // (Jace Browser does this for Jace's own apps), you're signed in here too, with no button.
  {
    let tried = false;
    try { tried = sessionStorage.getItem("jp-silent") === "1"; sessionStorage.setItem("jp-silent", "1"); } catch { tried = true; }
    if (!tried && !/[?&](signin_error|web=1)\b/.test(location.search)) {
      me().then((u) => { if (!u) location.replace("/api/jace/signin?prompt=none"); });
    }
  }
  const decodeVault = (payload) => JSON.parse(dec.decode(b64d(payload)));
  async function pull() {
    const r = await jace("GET", "sync");
    if (r.status === 404) return [null, 0];
    if (r.status !== 200) throw new ApiError(r.body.error_description || r.body.message || `Jace sync failed (${r.status}).`);
    return [decodeVault(r.body.payload), r.body.version];
  }
  let syncTimer = null, syncing = null;
  function scheduleSync(ms = 1500) { if (!jaceUser || !V.data) return; clearTimeout(syncTimer); syncTimer = setTimeout(syncNow, ms); }
  async function syncNow() {
    if (!(await me()) || !V.data) return sync;
    if (syncing) return syncing;
    syncing = (async () => {
      Object.assign(sync, { status: "syncing", error: null });
      try {
        for (let tries = 0; ; tries++) {
          const [remote, version] = await pull();
          if (remote) {
            let remoteData;
            try { remoteData = JSON.parse(dec.decode(await openSealed(V.key, remote.data, AAD_DATA))); }
            catch { throw new ApiError("The vault on Jace was made with a different key."); }
            if (mergeRemote(remoteData, remote)) await save();
          }
          const payload = b64e(enc.encode(JSON.stringify(await fileDict())));
          const r = await jace("PUT", "sync", { payload, device: "Jace Passwords web" }, { "If-Match": `"${version}"` });
          if (r.status === 412 && tries < 3) continue;
          if (r.status !== 200) throw new ApiError(r.body.error_description || r.body.message || `Jace sync failed (${r.status}).`);
          updateDevice({ syncVersion: r.body.version });
          Object.assign(sync, { status: "synced", at: nowIso(), version: r.body.version });
          break;
        }
      } catch (e) { Object.assign(sync, { status: "error", error: e.message }); }
      syncing = null;
      return sync;
    })();
    return syncing;
  }
  const changed = async () => { await save(); scheduleSync(); };

  // ---------- generator / strength / TOTP / cards / watchtower (generator.py, totp.py, security.py) ----------
  function randomPassword(o) {
    const length = Math.max(4, Math.min(128, +o.length || 20));
    let pools = [];
    if (o.lower !== false) pools.push("abcdefghijklmnopqrstuvwxyz");
    if (o.upper !== false) pools.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    if (o.digits !== false) pools.push("0123456789");
    if (o.symbols !== false) pools.push(D.symbols);
    if (!pools.length) pools.push("abcdefghijklmnopqrstuvwxyz");
    if (o.avoidAmbiguous) pools = pools.map((p) => [...p].filter((c) => !"Il1O0o|`'\"".includes(c)).join(""));
    const all = pools.join("");
    const chars = pools.slice(0, length).map((p) => choice([...p]));
    while (chars.length < length) chars.push(choice([...all]));
    for (let i = chars.length - 1; i > 0; i--) { const j = randBelow(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
    return chars.join("");
  }
  function generate(o = {}) {
    if (o.type === "passphrase") {
      const n = Math.max(3, Math.min(12, +o.words || 5));
      let w = Array.from({ length: n }, () => choice(D.words));
      if (o.capitalize !== false) w = w.map((x) => x[0].toUpperCase() + x.slice(1));
      if (o.number !== false) { const i = randBelow(n); w[i] += randBelow(10); }
      return w.join(o.separator ?? "-");
    }
    if (o.type === "pin") return Array.from({ length: Math.max(4, Math.min(12, +o.length || 6)) }, () => randBelow(10)).join("");
    return randomPassword(o);
  }
  function strength(pw) {
    if (!pw) return { score: 0, bits: 0, label: "Empty" };
    if (D.common.includes(pw.toLowerCase())) return { score: 0, bits: 0, label: "Very weak" };
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
    const len = [...pw].length, uniq = new Set(pw).size;
    const bits = len * Math.log2(Math.max(pool, 2)) * Math.min(1, 0.5 + uniq / Math.max(len, 1) / 2);
    const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { score, bits: Math.round(bits), label: ["Very weak", "Weak", "Fair", "Strong", "Very strong"][score] };
  }
  function totpParse(value) {
    value = String(value || "").trim();
    let cfg;
    if (/^otpauth:\/\//i.test(value)) {
      const u = new URL(value);
      if (u.host.toLowerCase() !== "totp") throw new ApiError("Only time-based (TOTP) codes are supported.");
      const q = Object.fromEntries([...u.searchParams].map(([k, v]) => [k.toLowerCase(), v]));
      const label = decodeURIComponent(u.pathname.replace(/^\/+/, ""));
      cfg = { secret: (q.secret || "").replace(/[\s-]/g, "").toUpperCase(), digits: +(q.digits || 6), period: +(q.period || 30),
        algorithm: (q.algorithm || "SHA1").toUpperCase(), issuer: q.issuer || (label.includes(":") ? label.split(":")[0] : ""),
        account: label.split(":").pop() };
    } else cfg = { secret: value.replace(/[\s-]/g, "").toUpperCase(), digits: 6, period: 30, algorithm: "SHA1", issuer: "", account: "" };
    if (!["SHA1", "SHA256", "SHA512"].includes(cfg.algorithm) || ![6, 7, 8].includes(cfg.digits) || cfg.period < 10 || cfg.period > 120) {
      throw new ApiError("Unsupported two-factor settings.");
    }
    base32(cfg.secret);
    return cfg;
  }
  function base32(s) {
    if (!s) throw new ApiError("That two-factor secret is empty.");
    const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let bits = 0, val = 0;
    const out = [];
    for (const c of s.replace(/=+$/, "")) {
      const i = A.indexOf(c);
      if (i < 0) throw new ApiError("That isn't a valid two-factor secret (it should be base32 letters A–Z and 2–7).");
      val = (val << 5) | i; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }
  async function totpCode(value, at = Date.now() / 1000) {
    const c = totpParse(value);
    const counter = Math.floor(at / c.period);
    const msg = new Uint8Array(8);
    new DataView(msg.buffer).setUint32(4, counter >>> 0);
    new DataView(msg.buffer).setUint32(0, Math.floor(counter / 0x100000000));
    const k = await subtle.importKey("raw", base32(c.secret), { name: "HMAC", hash: c.algorithm.replace("SHA", "SHA-") }, false, ["sign"]);
    const mac = new Uint8Array(await subtle.sign("HMAC", k, msg));
    const off = mac[mac.length - 1] & 15;
    const num = (new DataView(mac.buffer).getUint32(off) & 0x7fffffff) % 10 ** c.digits;
    return { code: String(num).padStart(c.digits, "0"), period: c.period, remaining: c.period - Math.floor(at % c.period), issuer: c.issuer };
  }
  function cardBrand(n) {
    const p4 = +n.slice(0, 4) || 0;
    if (n.startsWith("4")) return "Visa";
    if (/^5[1-5]/.test(n) || (p4 >= 2221 && p4 <= 2720)) return "Mastercard";
    if (/^3[47]/.test(n)) return "Amex";
    if (/^(6011|65|64[4-9])/.test(n)) return "Discover";
    if (p4 >= 3528 && p4 <= 3589) return "JCB";
    if (/^(36|30[0-5]|38)/.test(n)) return "Diners";
    if (/^(50|5[6-8]|6)/.test(n)) return "Maestro";
    return "";
  }
  function luhn(n) {
    const d = [...n].filter((c) => /\d/.test(c)).map(Number);
    if (d.length < 12) return false;
    let t = 0;
    d.reverse().forEach((x, i) => { if (i % 2) { x *= 2; if (x > 9) x -= 9; } t += x; });
    return t % 10 === 0;
  }
  function hostname(url) {
    url = String(url || "").trim();
    if (!url) return "";
    try { return new URL(/:\/\//.test(url) ? url : "https://" + url).hostname.toLowerCase().replace(/^www\./, ""); } catch { return ""; }
  }
  function site(url) {
    const h = hostname(url);
    if (!h || /^[\d.]+$/.test(h) || h === "localhost") return h;
    const parts = h.split(".");
    if (parts.length >= 3 && D.multiPartTlds.includes(parts.slice(-2).join("."))) return parts.slice(-3).join(".");
    return parts.slice(-2).join(".");
  }
  function report(items) {
    const logins = items.filter((i) => i.type === "login" && !i.deletedAt);
    const byPw = {};
    for (const i of logins) { const pw = i.fields?.password; if (pw) (byPw[pw] ||= []).push(i.id); }
    const r = { weak: [], reused: [], old: [], missing2fa: [], insecure: [], expiring: [] };
    const yearAgo = Date.now() - 365 * 864e5;
    for (const i of logins) {
      const f = i.fields || {}, pw = f.password || "";
      if (pw && strength(pw).score <= 1) r.weak.push(i.id);
      if (pw && byPw[pw].length > 1) r.reused.push(i.id);
      if (pw && Date.parse(i.passwordChangedAt || i.createdAt) < yearAgo) r.old.push(i.id);
      const urls = f.urls || [];
      if (!f.totp && !f.signInWith && !f.passkeys?.length && urls.some((u) => D.twoFaSites.includes(site(u)))) r.missing2fa.push(i.id);
      if (urls.some((u) => /^http:\/\//i.test(u.trim()) && !["localhost", "127.0.0.1"].includes(hostname(u)))) r.insecure.push(i.id);
    }
    const now = new Date();
    for (const c of items) {
      if (c.type !== "card" || c.deletedAt) continue;
      let m = +c.fields?.expMonth || 0, y = +c.fields?.expYear || 0;
      if (!m || !y) continue;
      if (y < 100) y += 2000;
      if ((y - now.getFullYear()) * 12 + (m - (now.getMonth() + 1)) <= 2) r.expiring.push(c.id);
    }
    const issues = new Set([...r.weak, ...r.reused, ...r.old, ...r.missing2fa, ...r.insecure]).size;
    const score = !logins.length ? 100 : Math.max(0, Math.round(100 - (100 * issues / logins.length) * 0.8 - r.expiring.length * 2));
    return { score, total: logins.length, ...r };
  }
  async function pwned(pw) {
    const h = [...new Uint8Array(await subtle.digest("SHA-1", enc.encode(pw)))].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    const res = await fetch(`https://api.pwnedpasswords.com/range/${h.slice(0, 5)}`, { headers: { "Add-Padding": "true" } });
    for (const line of (await res.text()).split("\n")) { const [suf, n] = line.trim().split(":"); if (suf === h.slice(5)) return +n; }
    return 0;
  }

  // ---------- CSV (importers.py) ----------
  function parseCsvRows(text) {
    const rows = []; let row = [], cur = "", q = false;
    text = text.replace(/^﻿/, "");
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) { if (c === '"' && text[i + 1] === '"') { cur += '"'; i++; } else if (c === '"') q = false; else cur += c; }
      else if (c === '"') q = true;
      else if (c === ",") { row.push(cur); cur = ""; }
      else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(cur); rows.push(row); row = []; cur = ""; }
      else cur += c;
    }
    if (cur || row.length) { row.push(cur); rows.push(row); }
    return rows.filter((r) => r.some((x) => x.trim()));
  }
  const COLS = { title: ["title", "name", "account", "item name"], url: ["url", "login_uri", "website", "web site", "login url", "urls", "origin"],
    username: ["username", "login_username", "user name", "login", "email", "login name"], password: ["password", "login_password"],
    totp: ["totp", "otpauth", "login_totp", "one-time password", "otp", "2fa"], notes: ["notes", "note", "extra", "comments"], type: ["type"] };
  function importCsv(text) {
    const [head, ...rows] = parseCsvRows(text);
    if (!head) return [];
    const names = head.map((h) => h.trim().toLowerCase());
    const out = [];
    for (const r of rows) {
      const row = Object.fromEntries(names.map((n, i) => [n, r[i] || ""]));
      const get = (k) => (COLS[k].map((n) => row[n]).find((v) => v) || "").trim();
      const kind = get("type").toLowerCase(), notes = get("notes"), url = get("url"), user = get("username"), pw = get("password");
      let title = get("title");
      if (["note", "securenote", "secure note"].includes(kind) || (!(url || user || pw) && notes)) { out.push({ type: "note", title: title || "Imported note", fields: { body: notes } }); continue; }
      if (!(url || user || pw)) continue;
      const urls = url.split(/[,\n]/).map((u) => u.trim()).filter(Boolean);
      title ||= (urls[0] ? hostname(urls[0]) : user) || "Imported login";
      out.push({ type: "login", title, fields: { username: user, password: pw, urls, totp: get("totp"), notes } });
    }
    return out;
  }
  function toCsv(items) {
    const q = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [["type", "title", "url", "username", "password", "totp", "notes"].join(",")];
    for (const i of items) {
      const f = i.fields || {};
      if (i.type === "login") lines.push(["login", i.title, (f.urls || []).join(","), f.username, f.password, f.totp, f.notes].map(q).join(","));
      else if (i.type === "note") lines.push(["note", i.title, "", "", "", "", f.body].map(q).join(","));
    }
    return lines.join("\r\n") + "\r\n";
  }

  // ---------- the API the app window calls (server.py's /api/*), answered in the page ----------
  async function state() {
    const st = { app: "Jace Passwords", version: VERSION, web: true, setup: exists(), locked: !V.data, hasSecretKey: !!device().secretKey,
      jace: await me(), vaultAccount: store.get("vault")?.account || null, sync, signinError: signinError, settings: V.data ? settings() : null };
    return st;
  }
  let signinError = null;
  {
    const u = new URL(location.href);
    if (u.searchParams.has("signin_error")) {
      signinError = u.searchParams.get("signin_error");
      u.searchParams.delete("signin_error");
      history.replaceState(null, "", u.pathname + u.search);
    }
  }

  async function api(method, route, body = {}) {
    const [path, qs] = route.split("?");
    const q = Object.fromEntries(new URLSearchParams(qs || ""));
    const [head, arg, sub] = path.replace(/^\/+|\/+$/g, "").split("/");
    switch (head) {
      case "state": return state();
      case "ping": if (V.data) touch(); return { ok: true };
      case "lock": lock(); return { ok: true };
      case "generate": { const pw = generate(body); return { password: pw, strength: strength(pw) }; }
      case "strength": return strength(body.password || "");
      case "card-check": { const n = String(body.number || "").replace(/\D/g, ""); return { brand: cardBrand(n), valid: luhn(n) }; }
      case "jace":
        if (arg === "signin") return { url: "/api/jace/signin" };
        if (arg === "signout") { await jace("POST", "signout"); jaceUser = null; try { sessionStorage.setItem("jp-silent", "1"); } catch { /* */ } Object.assign(sync, { status: "idle", error: null }); return { ok: true }; }
        if (arg === "remote") {
          if (!(await me())) throw new ApiError("Sign in with Jace first.");
          const [remote] = await pull();
          return { exists: !!remote, account: remote?.account || null };
        }
        break;
      case "setup": {
        if (exists()) throw new ApiError("A vault already exists in this browser.");
        if (body.mode === "restore") {
          if (!(await me())) throw new ApiError("Sign in with Jace first.");
          const [remote, version] = await pull();
          if (!remote) throw new ApiError("There's no vault on your Jace account yet.");
          await unlock(body.password || "", body.secretKey || "", remote);
          updateDevice({ syncVersion: version });
          return { ok: true };
        }
        if ((body.password || "").length < 10) throw new ApiError("Use at least 10 characters for your master password.");
        const sk = newSecretKey();
        V.key = rand(32); V.data = emptyData();
        const u = await me();
        await wrap(body.password, sk, u ? { id: u.id, username: u.username, name: u.name, picture: u.picture } : null);
        updateDevice({ secretKey: sk });
        await save(); scheduleSync(100);
        return { secretKey: sk };
      }
      case "unlock": await unlock(body.password || "", body.secretKey || null); scheduleSync(100); return { ok: true };
      case "sync": return syncNow();
      case "totp":
        if (arg === "parse") return totpParse(body.value);
        break;
      case "devices": return [];
      case "pair": throw new ApiError("The browser extension pairs with the Jace Passwords desktop app.");
    }

    const d = require_();
    switch (head) {
      case "vault": return snapshot();
      case "items": {
        if (method === "POST" && !arg) { const it = createItem(body); await changed(); return it; }
        if (!arg) return visible(true);
        if (method === "PUT") { const it = updateItem(arg, body); await changed(); return it; }
        if (method === "DELETE") {
          if (q.purge) purge(arg); else { const it = getItem(arg); it.deletedAt = it.updatedAt = nowIso(); }
          await changed(); return { ok: true };
        }
        if (method === "POST" && sub === "restore") { const it = getItem(arg); delete it.deletedAt; it.updatedAt = nowIso(); await changed(); return { ok: true }; }
        if (method === "POST" && sub === "used") { const it = getItem(arg); it.lastUsedAt = nowIso(); it.useCount = (it.useCount || 0) + 1; await save(); return { ok: true }; }
        if (sub === "totp") return totpCode(getItem(arg).fields?.totp || "");
        return getItem(arg);
      }
      case "trash": {
        const ids = d.items.filter((i) => i.deletedAt && !i.purged).map((i) => i.id);
        ids.forEach(purge); await changed(); return { purged: ids.length };
      }
      case "vaults": {
        const t = nowIso();
        if (method === "POST") {
          const v = { id: newId(), name: String(body.name || "Vault").trim().slice(0, 60), icon: body.icon || "🗂️", color: body.color || "#3ddc84",
            travelSafe: !!body.travelSafe, createdAt: t, updatedAt: t };
          d.vaults.push(v); await changed(); return v;
        }
        if (method === "PUT") {
          const v = d.vaults.find((x) => x.id === arg);
          if (!v) throw new ApiError("That vault doesn't exist.");
          for (const k of ["name", "icon", "color", "travelSafe"]) if (k in body) v[k] = body[k];
          v.updatedAt = t; await changed(); return v;
        }
        if (method === "DELETE") {
          if (d.vaults.length <= 1) throw new ApiError("You need at least one vault.");
          d.vaults = d.vaults.filter((v) => v.id !== arg);
          for (const i of d.items) if (i.vaultId === arg && !i.purged) { i.deletedAt = i.updatedAt = t; i.vaultId = d.vaults[0].id; }
          await changed(); return { ok: true };
        }
        return d.vaults;
      }
      case "settings": {
        const s = (d.settings ||= { ...DEFAULT_SETTINGS });
        for (const [k, v] of Object.entries(body)) if (k in DEFAULT_SETTINGS) s[k] = v;
        s.updatedAt = nowIso(); await changed(); return s;
      }
      case "generator-history":
        if (method === "POST") { (d.generatorHistory ||= []).unshift({ password: body.password || "", createdAt: nowIso() }); d.generatorHistory.length = Math.min(d.generatorHistory.length, 25); await save(); return { ok: true }; }
        return d.generatorHistory || [];
      case "totp-codes": {
        const out = {};
        for (const i of visible()) if (i.fields?.totp) { try { out[i.id] = await totpCode(i.fields.totp); } catch { /* bad secret */ } }
        return out;
      }
      case "watchtower":
        if (arg === "breach") {
          const breached = {}, seen = {};
          for (const i of visible()) {
            const pw = i.type === "login" ? i.fields?.password : null;
            if (!pw) continue;
            try { seen[pw] ??= await pwned(pw); } catch { throw new ApiError("Couldn't reach Have I Been Pwned. Check your connection."); }
            if (seen[pw]) breached[i.id] = seen[pw];
          }
          return { breached, checkedAt: nowIso() };
        }
        return report(visible());
      case "alias": {
        const base = String(body.base || settings().aliasBase || "").trim();
        if (!base.includes("@")) throw new ApiError("Set the email your aliases forward to first (Settings → Email aliases).");
        const [user, domain] = base.split("@");
        const tag = String(body.site || "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20) || [...rand(3)].map((b) => b.toString(16).padStart(2, "0")).join("");
        return { alias: `${user.split("+")[0]}+${tag}.${[...rand(2)].map((b) => b.toString(16).padStart(2, "0")).join("")}@${domain}`, forwardsTo: base };
      }
      case "import": { const items = importCsv(body.csv || ""); for (const it of items) createItem({ ...it, vaultId: body.vaultId }); await changed(); return { imported: items.length }; }
      case "export":
        if (!(await verifyPassword(body.password || ""))) throw new ApiError("That master password is wrong.");
        if (body.format === "csv") return { filename: "jace-passwords.csv", content: toCsv(visible()), mime: "text/csv" };
        return { filename: "jace-passwords-backup.json", content: JSON.stringify(await fileDict(), null, 1), mime: "application/json" };
      case "password": {
        if (!(await verifyPassword(body.current || ""))) throw new ApiError("Wrong master password or Secret Key.");
        if ((body.new || "").length < 10) throw new ApiError("Use at least 10 characters for your master password.");
        await wrap(body.new, device().secretKey); await changed(); return { ok: true };
      }
      case "emergency-kit":
        if (!(await verifyPassword(body.password || ""))) throw new ApiError("That master password is wrong.");
        return { secretKey: device().secretKey || "", account: await me(), jaceUrl: "https://jaceo.vercel.app" };
    }
    throw new ApiError("Not found.");
  }

  // auto-lock after the chosen idle time
  setInterval(() => {
    if (!V.data) return;
    const m = +settings().autoLockMinutes;
    if (m && Date.now() - V.lastActivity > m * 60000) lock();
  }, 10000);

  window.JPWeb = { api, scrypt, deriveKek, totpCode, _vault: V };
})();
