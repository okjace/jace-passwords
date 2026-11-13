"use strict";
/* The Jace Passwords vault engine in JavaScript: the same format, keys and encryption as the
 * desktop app (jace_passwords/crypto.py, vault.py, passkeys.py), so every copy opens the vault
 * you sync through Jace. Your master password and Secret Key never leave this code.
 *
 *   JPCore.create(env)  one vault: env gives it storage, a way to reach the Jace Passwords site
 *                       (/api/jace/*), and a few hooks. Used by:
 *     - the web app (bottom of this file: localStorage, same-site cookie)
 *     - the standalone browser extension (extension/background.js: extension storage, Bearer token)
 * On the desktop app (http://127.0.0.1:47620) the web app part does nothing. */
(() => {
  const D = globalThis.JP_DATA;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const subtle = crypto.subtle;
  const VERSION = "1.3.1";
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
  // PBKDF2-HMAC-SHA256 with one iteration, built from HMAC blocks: T_i = HMAC(pw, salt || i).
  // Firefox and Jace Browser refuse long native PBKDF2 outputs (scrypt asks for 1024 bytes) with
  // "The operation failed for an operation-specific reason". Same bytes as the native one.
  async function pbkdf2(pw, salt, len) {
    if (!pw.length) { // HMAC can't take an empty key; a short native PBKDF2 output works everywhere
      const k = await subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
      return new Uint8Array(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 1 }, k, len * 8));
    }
    const key = await subtle.importKey("raw", pw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const out = new Uint8Array(Math.ceil(len / 32) * 32);
    const msg = new Uint8Array(salt.length + 4);
    msg.set(salt);
    for (let i = 1; (i - 1) * 32 < len; i++) {
      new DataView(msg.buffer).setUint32(salt.length, i);
      out.set(new Uint8Array(await subtle.sign("HMAC", key, msg)), (i - 1) * 32);
    }
    return out.slice(0, len);
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
  async function deriveKek(password, secretKey, salt, kdf, jaceKey = null, deviceKey = null) {
    if (kdf.name === "device") { // no master password, not linked: opens on this device (crypto.py)
      if (!deviceKey) throw new ApiError("This vault opens only on the device that made it.");
      const k = await subtle.importKey("raw", deviceKey, "HKDF", false, ["deriveBits"]);
      return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("jace-passwords device unlock v1") }, k, 256));
    }
    if (kdf.name === "jace") { // no master password: unlocked with the Jace account (crypto.py)
      if (!jaceKey) throw new ApiError("Sign in with Jace to unlock this vault.");
      const k = await subtle.importKey("raw", jaceKey, "HKDF", false, ["deriveBits"]);
      return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: enc.encode("jace-passwords jace unlock v1") }, k, 256));
    }
    if (kdf.name !== "scrypt") throw new ApiError("Unknown key derivation.");
    const k1 = await scrypt(enc.encode(password), salt, kdf.n, kdf.r, kdf.p, 32);
    if (kdf.secretKey === false) return k1; // linked to Jace: master password only (crypto.py)
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

  function create(env) {
  // ---------- storage on this device (env.store: get(key, default) / set(key, value|null)) ----------
  const store = env.store;
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
  const usesSecretKey = (f) => { const k = f?.kdf || {}; return k.name !== "jace" && k.name !== "device" && k.secretKey !== false; };
  const keyMode = (f) => { const n = (f?.kdf || {}).name; return n === "jace" || n === "device" ? n : "password"; };
  const deviceKey = (create = false) => {
    let k = device().deviceKey;
    if (!k && create) { k = b64e(rand(32)); updateDevice({ deviceKey: k }); }
    return k ? b64d(k) : null;
  };
  async function jaceKey() {
    const r = await jace("GET", "vault-key");
    if (r.status !== 200) throw new ApiError(r.body.error_description || "Couldn't get your vault key. Sign in with Jace again.");
    const u = await me();
    if (!u || r.body.sub !== u.id) throw new ApiError("That key is for a different Jace account.");
    return b64d(r.body.key);
  }
  async function wrap(password, secretKey, account, useSk = usesSecretKey(V.meta), jk = null) {
    const salt = rand(16);
    const acct = account !== undefined ? account : V.meta.account ?? null;
    const kdf = password === null ? (jk ? { name: "jace", sub: acct?.id || "" } : { name: "device" }) : useSk ? { ...KDF } : { ...KDF, secretKey: false };
    const kek = await deriveKek(password, secretKey, salt, kdf, jk, kdf.name === "device" ? deviceKey(true) : null);
    V.meta = { format: FORMAT, account: acct, kdf,
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
    const usesSk = usesSecretKey(f);
    const sk = usesSk ? secretKey || device().secretKey : null;
    if (usesSk && !sk) throw new ApiError("Enter your Secret Key (it's on your Emergency Kit).");
    let jk = null;
    if (keyMode(f) === "jace") {
      const u = await me();
      if (u && f.kdf.sub && u.id !== f.kdf.sub) throw new ApiError("This vault belongs to another Jace account. Sign in with that one.");
      jk = await jaceKey();
    }
    const kek = await deriveKek(password, sk, b64d(f.salt), f.kdf, jk, deviceKey());
    const key = await openSealed(kek, f.wrappedKey, AAD_KEY);
    V.data = JSON.parse(dec.decode(await openSealed(key, f.data, AAD_DATA)));
    V.key = key;
    V.meta = Object.fromEntries(Object.entries(f).filter(([k]) => k !== "data" && k !== "updatedAt"));
    if (secretKey && usesSk) updateDevice({ secretKey });
    if (file) await save();
    touch();
  }
  function lock() { V.key = null; V.data = null; }

  async function verifyPassword(pw) {
    if (keyMode(store.get("vault")) !== "password") return !!V.data; // no master password to check
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
    const gone = { ...(d.deletedVaults || {}) };
    for (const [id, t] of Object.entries(remoteData.deletedVaults || {})) if (t > (gone[id] || "")) { gone[id] = t; changed = true; }
    if (Object.keys(gone).length) {
      d.deletedVaults = gone;
      const keep = d.vaults.filter((v) => !(gone[v.id] && (v.updatedAt || "") <= gone[v.id]));
      if (keep.length && keep.length !== d.vaults.length) {
        const ids = new Set(keep.map((v) => v.id));
        for (const i of d.items) if (!ids.has(i.vaultId)) i.vaultId = keep[0].id;
        d.vaults = keep;
      }
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
  // env.jace(method, path, body, headers) -> {status, body}: the Jace Passwords site's /api/jace/<path>
  const jace = (method, path, body, headers = {}) => env.jace(method, path, body, headers);
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
  const forgetUser = () => { jaceUser = undefined; mePromise = null; };
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
        if (keyMode(V.meta) === "device") { await wrap(null, null, undefined, false, await jaceKey()); await save(); }
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
      } catch (e) {
        const raw = typeof DOMException !== "undefined" && e instanceof DOMException;
        Object.assign(sync, { status: "error", error: raw ? `Your browser's encryption failed while syncing (${e.name}: ${e.message}).` : e.message });
      }
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
  // Established public data for Watchtower (security.py): 2fa.directory, the passkeys directory and
  // Have I Been Pwned's breached websites (through the Jace Passwords site: its API has no CORS).
  async function watchtowerData() {
    const cached = store.get("wtcache");
    if (cached && cached.at > Date.now() - 864e5 && cached.tfa && cached.passkeys && cached.breaches) return cached;
    const get = async (url) => { const r = await fetch(url); if (!r.ok) throw new Error(r.status); return r.json(); };
    const fresh = { at: Date.now() };
    try {
      const raw = await get("https://api.2fa.directory/v3/tfa.json");
      fresh.tfa = {};
      for (const [, e] of raw) { const info = { methods: e.tfa || [], doc: e.documentation || "" }; for (const d of [e.domain, ...(e["additional-domains"] || [])]) if (d) fresh.tfa[d.toLowerCase()] = info; }
    } catch { if (cached?.tfa) fresh.tfa = cached.tfa; }
    try {
      const raw = await get("https://passkeys-api.2fa.directory/v1/supported.json");
      fresh.passkeys = Object.fromEntries(Object.entries(raw).map(([d, v]) => [d.toLowerCase(), { passwordless: !!v.passwordless, mfa: !!v.mfa, doc: v.documentation || "" }]));
    } catch { if (cached?.passkeys) fresh.passkeys = cached.passkeys; }
    try {
      const r = await jace("GET", "breaches");
      if (r.status === 200) fresh.breaches = r.body; else throw new Error(r.status);
    } catch { if (cached?.breaches) fresh.breaches = cached.breaches; }
    try { store.set("wtcache", fresh); } catch { /* too big for this browser's storage: just don't cache */ }
    return fresh;
  }
  const lookup = (table, url) => (table ? table[hostname(url)] || table[site(url)] || null : null);
  function report(items, data = {}) {
    const tfa = data.tfa || {}, pkSites = data.passkeys || {}, breaches = data.breaches || {};
    const logins = items.filter((i) => i.type === "login" && !i.deletedAt);
    const byPw = {};
    for (const i of logins) { const pw = i.fields?.password; if (pw) (byPw[pw] ||= []).push(i.id); }
    const r = { weak: [], reused: [], old: [], missing2fa: [], insecure: [], expiring: [], compromised: [], passkeysAvailable: [] };
    const details = {};
    const yearAgo = Date.now() - 365 * 864e5;
    for (const i of logins) {
      const f = i.fields || {}, pw = f.password || "";
      if (pw && strength(pw).score <= 1) r.weak.push(i.id);
      if (pw && byPw[pw].length > 1) r.reused.push(i.id);
      if (pw && Date.parse(i.passwordChangedAt || i.createdAt) < yearAgo) r.old.push(i.id);
      const urls = f.urls || [];
      const info = {};
      const t = urls.map((u) => lookup(tfa, u)).find(Boolean);
      if (t) info.tfa = t;
      if (!f.totp && !f.signInWith && !f.passkeys?.length && ((t && t.methods.length) || (!data.tfa && urls.some((u) => D.twoFaSites.includes(site(u)))))) r.missing2fa.push(i.id);
      const pk = urls.map((u) => lookup(pkSites, u)).find(Boolean);
      if (pk) { info.passkeys = pk; if (!f.passkeys?.length && !f.signInWith) r.passkeysAvailable.push(i.id); }
      const changed = (i.passwordChangedAt || i.createdAt || "").slice(0, 10);
      const hits = urls.flatMap((u) => lookup(breaches, u) || []);
      const newest = (list) => list.reduce((a, b) => ((b.added || b.date) > (a.added || a.date) ? b : a));
      const newer = hits.filter((b) => b.passwords && pw && (!changed || ((b.added || "").slice(0, 10) || b.date) >= changed));
      if (newer.length) { r.compromised.push(i.id); info.breach = newest(newer); }
      else if (hits.length) info.pastBreach = newest(hits);
      if (urls.some((u) => /^http:\/\//i.test(u.trim()) && !["localhost", "127.0.0.1"].includes(hostname(u)))) r.insecure.push(i.id);
      if (Object.keys(info).length) details[i.id] = info;
    }
    const now = new Date();
    for (const c of items) {
      if (c.type !== "card" || c.deletedAt) continue;
      let m = +c.fields?.expMonth || 0, y = +c.fields?.expYear || 0;
      if (!m || !y) continue;
      if (y < 100) y += 2000;
      if ((y - now.getFullYear()) * 12 + (m - (now.getMonth() + 1)) <= 2) r.expiring.push(c.id);
    }
    // Vulnerabilities count fully; recommendations (old password, 2FA you could turn on) a quarter.
    const vulnerable = new Set([...r.weak, ...r.reused, ...r.compromised, ...r.insecure]);
    const advice = new Set([...r.old, ...r.missing2fa].filter((id) => !vulnerable.has(id)));
    const penalty = logins.length ? (vulnerable.size + 0.25 * advice.size) / logins.length : 0;
    const score = !logins.length ? 100 : Math.max(0, Math.round(100 - 100 * penalty * 0.8 - r.expiring.length * 2));
    return { score, total: logins.length, ...r, details, sources: { tfa: !!data.tfa, passkeys: !!data.passkeys, breaches: !!data.breaches } };
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
  let autoOpened = false;
  async function autoOpen() {
    if (autoOpened || V.data || !exists()) return;
    autoOpened = true;
    const mode = keyMode(store.get("vault"));
    if (mode === "device" || (mode === "jace" && (await me()))) { try { await unlock(null, null); scheduleSync(100); } catch { /* lock screen has a button */ } }
  }
  async function state() {
    await autoOpen();
    const st = { app: "Jace Passwords", version: VERSION, web: !!env.web, extension: !!env.extension, setup: exists(), locked: !V.data, hasSecretKey: !!device().secretKey, keyMode: exists() ? keyMode(store.get("vault")) : null,
      usesSecretKey: exists() ? usesSecretKey(store.get("vault")) : null,
      needsSecretKey: exists() && usesSecretKey(store.get("vault")) && !device().secretKey,
      jace: await me(), vaultAccount: store.get("vault")?.account || null, sync, signinError: signinError, settings: V.data ? settings() : null };
    return st;
  }
  let signinError = env.signinError || null;

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
        if (arg === "signin") return { url: env.signinUrl || "/api/jace/signin" };
        if (arg === "signout") { await (env.signout ? env.signout() : jace("POST", "signout")); jaceUser = null; Object.assign(sync, { status: "idle", error: null }); return { ok: true }; }
        if (arg === "remote") {
          if (!(await me())) throw new ApiError("Sign in with Jace first.");
          const [remote] = await pull();
          return { exists: !!remote, account: remote?.account || null, usesSecretKey: remote ? usesSecretKey(remote) : false, keyMode: remote ? keyMode(remote) : null };
        }
        break;
      case "setup": {
        if (exists()) throw new ApiError("A vault already exists in this browser.");
        if (body.skipPassword) { // no master password: the Jace key if signed in, else this device's
          const u = await me();
          V.key = rand(32); V.data = emptyData();
          await wrap(null, null, u ? { id: u.id, username: u.username, name: u.name, picture: u.picture } : null, false, u ? await jaceKey() : null);
          updateDevice({ secretKey: null });
          await save(); scheduleSync(100);
          return { secretKey: null };
        }
        if (body.mode === "restore") {
          if (!(await me())) throw new ApiError("Sign in with Jace first.");
          const [remote, version] = await pull();
          if (!remote) throw new ApiError("There's no vault on your Jace account yet.");
          await unlock(body.password || "", body.secretKey || "", remote);
          updateDevice({ syncVersion: version });
          return { ok: true };
        }
        if (!body.password) throw new ApiError("Enter a master password.");
        const u0 = await me();
        const sk = u0 ? null : newSecretKey(); // linked to Jace: no Secret Key
        V.key = rand(32); V.data = emptyData();
        const u = await me();
        await wrap(body.password, sk, u ? { id: u.id, username: u.username, name: u.name, picture: u.picture } : null, !!sk);
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
          if (!d.vaults.some((v) => v.id === arg)) throw new ApiError("That vault doesn't exist.");
          (d.deletedVaults ||= {})[arg] = t; // so sync doesn't bring it back from another device's copy
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
        return report(visible(), await watchtowerData());
      case "alias": {
        const base = String(body.base || settings().aliasBase || "").trim();
        if (!base.includes("@")) throw new ApiError("Set the email your aliases forward to first (Settings → Email aliases).");
        const [user, domain] = base.split("@");
        const tag = String(body.site || "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 20) || [...rand(3)].map((b) => b.toString(16).padStart(2, "0")).join("");
        return { alias: `${user.split("+")[0]}+${tag}.${[...rand(2)].map((b) => b.toString(16).padStart(2, "0")).join("")}@${domain}`, forwardsTo: base };
      }
      case "import-items": { // parsed in the app window (import.js); passkeys link to the login you already have
        const out = { imported: 0, passkeys: 0, linked: 0 };
        for (const it of (body.items || []).slice(0, 20000)) {
          if (!it || !ITEM_TYPES.includes(it.type)) continue;
          const fields = { ...(it.fields || {}) };
          const pks = (fields.passkeys || []).filter((p) => p && p.credentialId && p.rpId && p.privateKey);
          delete fields.passkeys;
          if (it.type === "login" && pks.length) {
            const sites = new Set([...(fields.urls || []).map(site), ...pks.map((p) => site("https://" + p.rpId))]);
            const user = fields.username || "";
            const target = visible().find((i) => i.type === "login" && (i.fields?.urls || []).some((u) => sites.has(site(u)))
              && (!user || !i.fields?.username || i.fields.username === user));
            if (target) {
              const t = getItem(target.id), f = (t.fields ||= {});
              const have = new Set((f.passkeys || []).map((p) => p.credentialId));
              const fresh = pks.filter((p) => !have.has(p.credentialId));
              f.passkeys = [...(f.passkeys || []), ...fresh];
              if (!f.passkeys.length) delete f.passkeys;
              for (const k of ["username", "password", "totp", "notes"]) if (!f[k] && fields[k]) f[k] = fields[k];
              f.urls = [...new Set([...(f.urls || []), ...(fields.urls || [])])];
              t.updatedAt = nowIso();
              out.passkeys += fresh.length; out.linked += fresh.length;
              continue;
            }
            fields.passkeys = pks; out.passkeys += pks.length;
          }
          createItem({ ...it, fields, vaultId: body.vaultId });
          out.imported++;
        }
        await changed();
        return out;
      }
      case "passkey-move": { // link a passkey to another login
        const src = getItem(body.fromId || ""), dst = getItem(body.toId || "");
        if (dst.type !== "login") throw new ApiError("Passkeys can only be linked to logins.");
        const pk = (src.fields?.passkeys || []).find((p) => p.credentialId === body.credentialId);
        if (!pk) throw new ApiError("That passkey isn't on this login.");
        if (src !== dst) {
          src.fields.passkeys = src.fields.passkeys.filter((p) => p !== pk);
          if (!src.fields.passkeys.length) delete src.fields.passkeys;
          (dst.fields ||= {}).passkeys = [...(dst.fields.passkeys || []), pk];
          const url = "https://" + pk.rpId;
          if (pk.rpId && !(dst.fields.urls || []).some((u) => site(u) === site(url))) dst.fields.urls = [...(dst.fields.urls || []), url];
          if (!dst.fields.username && pk.userName) dst.fields.username = pk.userName;
          src.updatedAt = dst.updatedAt = nowIso();
          await changed();
        }
        return { ok: true, id: dst.id };
      }
      case "import": { const items = importCsv(body.csv || ""); for (const it of items) createItem({ ...it, vaultId: body.vaultId }); await changed(); return { imported: items.length }; }
      case "export":
        if (!(await verifyPassword(body.password || ""))) throw new ApiError("That master password is wrong.");
        if (body.format === "csv") return { filename: "jace-passwords.csv", content: toCsv(visible()), mime: "text/csv" };
        return { filename: "jace-passwords-backup.json", content: JSON.stringify(await fileDict(), null, 1), mime: "application/json" };
      case "key-mode": {
        if (!(await verifyPassword(body.current || ""))) throw new ApiError("That master password is wrong.");
        if (body.mode === "jace") { await wrap(null, null, undefined, false, await jaceKey()); updateDevice({ secretKey: null }); }
        else if (body.mode === "device") { await wrap(null, null, undefined, false, null); updateDevice({ secretKey: null }); }
        else {
          if (!body.password) throw new ApiError("Enter a master password.");
          await wrap(body.password, null, undefined, false);
        }
        await changed(); return { ok: true };
      }
      case "password": {
        if (!(await verifyPassword(body.current || ""))) throw new ApiError("Wrong master password or Secret Key.");
        if (!body.new) throw new ApiError("Enter a master password.");
        const fromJace = keyMode(V.meta) !== "password";
        await wrap(body.new, fromJace ? null : device().secretKey || null, undefined, fromJace ? false : usesSecretKey(V.meta)); await changed(); return { ok: true };
      }
      case "secret-key": {
        if (!(await verifyPassword(body.password || ""))) throw new ApiError("That master password is wrong.");
        if (!body.use && !(await me())) throw new ApiError("Sign in with Jace first: without a Secret Key, your Jace account protects the synced copy.");
        const sk = body.use ? device().secretKey || newSecretKey() : null;
        await wrap(body.password, sk, undefined, !!body.use);
        updateDevice({ secretKey: sk });
        await changed();
        return { secretKey: sk };
      }
      case "emergency-kit":
        if (!(await verifyPassword(body.password || ""))) throw new ApiError("That master password is wrong.");
        return { secretKey: device().secretKey || "", account: await me(), jaceUrl: "https://jaceo.vercel.app" };
    }
    throw new ApiError("Not found.");
  }

  // ---------- autofill and passkeys for the browser extension (server.py ext_api, passkeys.py) ----------
  function matches(item, url) { // 0 no match, 1 same site, 2 same host (security.matches)
    if (item.type !== "login" || item.deletedAt) return 0;
    const h = hostname(url), s = site(url);
    let best = 0;
    for (const u of item.fields?.urls || []) {
      const uh = hostname(u);
      if (uh && uh === h) return 2;
      if (s && site(u) === s) best = 1;
    }
    return best;
  }
  function summary(i) {
    const f = i.fields || {};
    const s = { id: i.id, type: i.type, title: i.title || "", vaultId: i.vaultId, favorite: !!i.favorite };
    if (i.type === "login") Object.assign(s, { username: f.username || "", urls: f.urls || [], hasTotp: !!f.totp, signInWith: f.signInWith || null,
      hasPassword: !!f.password, passkeys: (f.passkeys || []).length });
    else if (i.type === "card") { const n = String(f.number || "").replace(/\D/g, ""); Object.assign(s, { last4: n.slice(-4), brand: f.brand || cardBrand(n), cardType: f.cardType || "credit", cardholder: f.cardholder || "" }); }
    else if (i.type === "identity") Object.assign(s, { name: f.fullName || "", email: f.email || "" });
    else if (i.type === "alias") s.alias = f.alias || "";
    return s;
  }

  const cat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };
  const b64u = (u8) => b64e(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const b64uDec = (s) => b64d(String(s).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(s).length + 3) % 4));
  const sha256 = async (u8) => new Uint8Array(await subtle.digest("SHA-256", u8));
  const AAGUID = Uint8Array.from("6a61636570617373776f7264732d3031".match(/../g).map((h) => parseInt(h, 16)));
  function cborHead(major, n) {
    if (n < 24) return [major << 5 | n];
    if (n < 256) return [major << 5 | 24, n];
    if (n < 65536) return [major << 5 | 25, n >> 8, n & 255];
    return [major << 5 | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
  }
  function cbor(v) {
    if (typeof v === "number") return Uint8Array.from(v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v));
    if (v instanceof Uint8Array) return cat(Uint8Array.from(cborHead(2, v.length)), v);
    if (typeof v === "string") { const e = enc.encode(v); return cat(Uint8Array.from(cborHead(3, e.length)), e); }
    if (Array.isArray(v)) return cat(Uint8Array.from(cborHead(4, v.length)), ...v.map(cbor));
    const entries = v instanceof Map ? [...v] : Object.entries(v);
    return cat(Uint8Array.from(cborHead(5, entries.length)), ...entries.flatMap(([k, x]) => [cbor(k), cbor(x)]));
  }
  class PasskeyError extends Error { constructor(msg, name = "NotAllowedError") { super(`${name}: ${msg}`); } }
  function checkOrigin(origin, rpId) {
    let u;
    try { u = new URL(origin); } catch { throw new PasskeyError("Bad origin.", "SecurityError"); }
    const host = u.hostname.toLowerCase(), rp = String(rpId || "").toLowerCase();
    const local = host === "localhost" || host.endsWith(".localhost");
    if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new PasskeyError("Passkeys only work on secure (https) sites.", "SecurityError");
    if (!rp || !(host === rp || (host.endsWith("." + rp) && rp.includes(".")))) throw new PasskeyError(`${host} can't use passkeys for ${rp}.`, "SecurityError");
  }
  function derSignature(raw) {
    const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.slice(i); if (b[0] & 0x80) b = cat(Uint8Array.of(0), b); return cat(Uint8Array.of(2, b.length), b); };
    const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
    return cat(Uint8Array.of(0x30, r.length + s.length), r, s);
  }
  async function authData(rpId, flags, attested = new Uint8Array()) {
    return cat(await sha256(enc.encode(rpId)), Uint8Array.of(flags, 0, 0, 0, 0), attested);
  }
  function passkeysFor(rpId) {
    const ids = new Set(visible().map((i) => i.id));
    const out = [];
    for (const i of require_().items) if (ids.has(i.id)) for (const p of i.fields?.passkeys || []) if (p.rpId === rpId) out.push([i, p]);
    return out;
  }
  // The login a new passkey belongs with (vault.pick_login_for_passkey): same site and the same
  // account if one says so, else one with no username, else the site's only login.
  function pickLoginForPasskey(items, url, pk) {
    const logins = items.filter((i) => matches(i, url));
    if (!logins.length) return null;
    const names = new Set([pk.userName, pk.userDisplayName].filter((n) => n && n.trim()).map((n) => n.trim().toLowerCase()));
    const user = (i) => String(i.fields?.username || "").trim().toLowerCase();
    return logins.find((i) => user(i) && names.has(user(i))) || logins.find((i) => !user(i))
      || (logins.length === 1 && !(logins[0].fields?.passkeys || []).some((p) => p.userHandle && p.userHandle !== pk.userHandle) ? logins[0] : null);
  }
  async function passkeyCreate({ rpId, origin, clientDataJSON, user = {}, algs = [], rpName = "", exclude = [] }) {
    checkOrigin(origin, rpId);
    const cdj = b64uDec(clientDataJSON), cd = JSON.parse(dec.decode(cdj));
    if (cd.type !== "webauthn.create" || cd.origin !== origin) throw new PasskeyError("Bad client data.", "SecurityError");
    if (algs.length && !algs.includes(-7)) throw new PasskeyError("This site doesn't accept the passkey type Jace Passwords makes.", "NotSupportedError");
    const existing = new Set(passkeysFor(rpId).map(([, p]) => p.credentialId));
    if (exclude.some((id) => existing.has(id))) throw new PasskeyError("You already have a passkey for this account in Jace Passwords.", "InvalidStateError");
    const kp = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const raw = new Uint8Array(await subtle.exportKey("raw", kp.publicKey));
    const credId = rand(16);
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33, 65)]]));
    const attested = cat(AAGUID, Uint8Array.of(0, credId.length), credId, cose);
    const ad = await authData(rpId, 0x5d, attested);
    const stored = { credentialId: b64u(credId), rpId, userHandle: user.id || "", userName: String(user.name || "").slice(0, 200),
      userDisplayName: String(user.displayName || "").slice(0, 200), alg: -7,
      privateKey: b64e(new Uint8Array(await subtle.exportKey("pkcs8", kp.privateKey))), createdAt: nowIso() };
    // save it on the login for that site and username (vault.save_passkey)
    for (const [i, p] of passkeysFor(rpId)) if (p.userHandle === stored.userHandle) i.fields.passkeys = i.fields.passkeys.filter((x) => x !== p);
    const url = "https://" + rpId;
    let target = pickLoginForPasskey(visible(), url, stored);
    target = target ? getItem(target.id) : createItem({ type: "login", title: rpName || hostname(url), fields: { username: stored.userName, urls: [url] } });
    target.fields ||= {};
    if (!target.fields.username) target.fields.username = stored.userName;
    (target.fields.passkeys ||= []).push(stored);
    target.updatedAt = nowIso();
    await changed();
    return { credentialId: stored.credentialId, clientDataJSON: b64u(cdj), attestationObject: b64u(cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", ad]]))),
      authenticatorData: b64u(ad), publicKey: b64u(new Uint8Array(await subtle.exportKey("spki", kp.publicKey))), publicKeyAlgorithm: -7,
      transports: ["internal", "hybrid"], itemId: target.id, title: target.title };
  }
  async function passkeyGet({ rpId, origin, clientDataJSON, credentialId }) {
    checkOrigin(origin, rpId);
    const cdj = b64uDec(clientDataJSON), cd = JSON.parse(dec.decode(cdj));
    if (cd.type !== "webauthn.get" || cd.origin !== origin) throw new PasskeyError("Bad client data.", "SecurityError");
    const hit = passkeysFor(rpId).find(([, p]) => p.credentialId === credentialId);
    if (!hit) throw new PasskeyError("That passkey isn't in your vault.");
    const [item, p] = hit;
    const key = await subtle.importKey("pkcs8", b64d(p.privateKey), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
    const ad = await authData(rpId, 0x1d);
    const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, cat(ad, await sha256(cdj))));
    p.lastUsedAt = item.lastUsedAt = nowIso();
    item.useCount = (item.useCount || 0) + 1;
    await changed();
    return { credentialId: p.credentialId, clientDataJSON: b64u(cdj), authenticatorData: b64u(ad), signature: b64u(derSignature(sig)), userHandle: p.userHandle || "" };
  }

  async function extApi(route, body = {}) {
    checkAutoLock();
    if (route === "status") await autoOpen();
    if (route === "status") return { locked: !V.data, setup: exists(), account: await me(), version: VERSION, keyMode: exists() ? keyMode(store.get("vault")) : null };
    if (route === "unlock") { await unlock(body.password || "", null); scheduleSync(100); return { ok: true }; }
    if (route === "lock") { lock(); return { ok: true }; }
    if (route === "generate") { const pw = generate(body || {}); return { password: pw, strength: strength(pw) }; }
    require_();
    if (route === "match") {
      const url = body.url || "";
      const scored = visible().map((i) => [matches(i, url), i]).filter(([n]) => n).sort((a, b) => b[0] - a[0] || a[1].title.localeCompare(b[1].title));
      return { site: site(url), logins: scored.map(([, i]) => summary(i)),
        cards: visible().filter((i) => i.type === "card").map(summary), identities: visible().filter((i) => i.type === "identity").map(summary) };
    }
    if (route === "search") {
      const q = String(body.q || "").toLowerCase();
      return visible().filter((i) => [i.title, i.fields?.username, ...(i.fields?.urls || [])].join(" ").toLowerCase().includes(q)).slice(0, 50).map(summary);
    }
    if (route === "fill") {
      const it = getItem(body.id || ""), f = it.fields || {};
      it.lastUsedAt = nowIso(); it.useCount = (it.useCount || 0) + 1; await save();
      const out = { type: it.type, title: it.title };
      if (it.type === "login") { out.username = f.username || ""; out.password = f.password || ""; if (f.totp) { try { out.totp = (await totpCode(f.totp)).code; } catch { /* bad secret */ } } }
      else if (it.type === "card") for (const k of ["cardholder", "number", "expMonth", "expYear", "cvv", "zip"]) out[k] = f[k] || "";
      else if (it.type === "identity") for (const k of ["fullName", "firstName", "lastName", "email", "phone", "address1", "address2", "city", "state", "zip", "country", "company", "birthday"]) out[k] = f[k] || "";
      return out;
    }
    if (route === "save-check" || route === "save") {
      const { url = "", username = "", password = "" } = body;
      for (const i of visible()) {
        if (matches(i, url) && (i.fields?.username || "") === username) {
          if (route === "save-check") return { status: i.fields?.password === password ? "unchanged" : "update", title: i.title };
          if (i.fields?.password === password) return { status: "unchanged", id: i.id };
          updateItem(i.id, { fields: { ...i.fields, password } }); await changed();
          return { status: "updated", id: i.id };
        }
      }
      if (route === "save-check") return { status: "new", title: site(url) };
      if (!password) throw new ApiError("No password to save.");
      const host = hostname(url);
      const it = createItem({ type: "login", title: body.title || site(url) || host, fields: { username, password, urls: host ? ["https://" + host] : [] } });
      await changed();
      return { status: "created", id: it.id };
    }
    if (route === "save-check-item" || route === "save-item") { // cards and addresses typed into forms
      const kind = body.type;
      if (kind !== "card" && kind !== "identity") throw new ApiError("Unknown item type.");
      const fields = Object.fromEntries(Object.entries(body.fields || {}).map(([k, x]) => [k, String(x ?? "").trim()]).filter(([k, x]) => x && k !== "cvv"));
      const nrm = (x) => String(x || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
      const digits = (x) => String(x || "").replace(/\D/g, "");
      let title, summary;
      if (kind === "card") {
        const num = digits(fields.number), brand = cardBrand(num) || "Card";
        const exp = fields.expMonth ? `${fields.expMonth}/${String(fields.expYear || "").slice(-2)}` : "";
        title = `${brand} •••• ${num.slice(-4)}`;
        summary = [title, fields.cardholder, exp && "expires " + exp].filter(Boolean).join(" · ");
      } else {
        const name = fields.fullName || [fields.firstName, fields.lastName].filter(Boolean).join(" ");
        title = name || fields.email || fields.address1 || "Address";
        summary = [name, [fields.address1, fields.city, fields.state, fields.zip].filter(Boolean).join(", "), fields.email, fields.phone].filter(Boolean).join(" · ");
      }
      const match = visible().find((i) => i.type === kind && (kind === "card"
        ? fields.number && digits(i.fields?.number) === digits(fields.number)
        : fields.address1 ? nrm(i.fields?.address1) === nrm(fields.address1) : fields.email && nrm(i.fields?.email) === nrm(fields.email)));
      if (route === "save-check-item") {
        if (!match) return { status: "new", title, summary };
        const same = Object.entries(fields).every(([k, x]) => nrm(match.fields?.[k]) === nrm(x));
        return { status: same ? "unchanged" : "update", title: match.title, summary };
      }
      if (match) { updateItem(match.id, { fields: { ...match.fields, ...fields } }); await changed(); return { status: "updated", id: match.id }; }
      if (kind === "card") { fields.cardType ||= "credit"; fields.brand = cardBrand(digits(fields.number)); }
      const it = createItem({ type: kind, title, fields });
      await changed();
      return { status: "created", id: it.id };
    }
    if (route === "passkey/list") {
      const allow = new Set(body.allow || []);
      return passkeysFor(body.rpId || "").filter(([, p]) => !allow.size || allow.has(p.credentialId))
        .map(([i, p]) => ({ credentialId: p.credentialId, userName: p.userName || i.fields?.username || "", userDisplayName: p.userDisplayName || "", title: i.title, itemId: i.id }));
    }
    if (route === "passkey/create") return passkeyCreate(body);
    if (route === "passkey/get") return passkeyGet(body);
    throw new ApiError("Not found.");
  }

  // auto-lock after the chosen idle time
  function checkAutoLock() {
    if (!V.data) return;
    const m = +settings().autoLockMinutes;
    if (m && keyMode(V.meta) !== "device" && Date.now() - V.lastActivity > m * 60000) lock();
  }
  setInterval(checkAutoLock, 10000);

  // ---------- keeping an unlocked vault across restarts of the extension's background ----------
  function exportSession() { return V.key ? { key: b64e(V.key), lastActivity: V.lastActivity } : null; }
  async function restoreSession(sess) {
    const f = store.get("vault");
    if (!sess?.key || !f || V.data) return !!V.data;
    try {
      const key = b64d(sess.key);
      V.data = JSON.parse(dec.decode(await openSealed(key, f.data, AAD_DATA)));
      V.key = key;
      V.meta = Object.fromEntries(Object.entries(f).filter(([k]) => k !== "data" && k !== "updatedAt"));
      V.lastActivity = sess.lastActivity || Date.now();
      checkAutoLock();
    } catch { V.key = null; V.data = null; }
    return !!V.data;
  }

  // Save the vault from your Jace account here (still encrypted), ready to unlock.
  async function fetchRemote() {
    const [remote, version] = await pull();
    if (!remote) return false;
    store.set("vault", remote);
    updateDevice({ syncVersion: version });
    return true;
  }

  // A browser crypto failure (DOMException "OperationError" and friends) says nothing useful on its
  // own; say what Jace Passwords was doing, so it can be traced.
  const explain = (fn, what) => async (a, b, c) => {
    try { return await fn(a, b, c); } catch (e) {
      if (e && typeof DOMException !== "undefined" && e instanceof DOMException && !e.locked) {
        throw new ApiError(`Your browser's encryption failed while ${what(a, b)} (${e.name}: ${e.message}). Please report this.`);
      }
      throw e;
    }
  };
  const apiSafe = explain(api, (m, r) => `doing ${m} ${String(r).split("?")[0]}`);
  const extSafe = explain(extApi, (r) => `doing ${r}`);
  return { api: apiSafe, ext: extSafe, fetchRemote, me, forgetUser, lock, isUnlocked: () => !!V.data, exists, keyMode: () => (exists() ? keyMode(store.get("vault")) : null),
    exportSession, restoreSession, checkAutoLock, syncNow, _vault: V };
  } // create

  globalThis.JPCore = { create, scrypt, deriveKek };

  // ---------- the web app (https://jace-passwords.vercel.app) ----------
  if (typeof window === "undefined" || typeof location === "undefined" || !location.protocol.startsWith("http")) return;
  const isWeb = location.protocol === "https:" || /[?&]web=1\b/.test(location.search) || sessionStorage.getItem("jp-web") === "1";
  if (!isWeb) return;
  try { sessionStorage.setItem("jp-web", "1"); } catch { /* private mode */ }
  let signinError = null;
  {
    const u = new URL(location.href);
    if (u.searchParams.has("signin_error")) {
      signinError = u.searchParams.get("signin_error");
      u.searchParams.delete("signin_error");
      history.replaceState(null, "", u.pathname + u.search);
    }
  }
  const web = create({
    web: true,
    signinError,
    store: {
      get(k, d = null) { try { const v = localStorage.getItem("jp-" + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
      set(k, v) { try { v === null ? localStorage.removeItem("jp-" + k) : localStorage.setItem("jp-" + k, JSON.stringify(v)); } catch { throw new Error("This browser won't let Jace Passwords save your vault (private mode?)."); } },
    },
    async jace(method, path, body, headers = {}) {
      const r = await fetch("/api/jace/" + path, { method, credentials: "same-origin",
        headers: { "X-Jace-Passwords": "1", ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
        body: body ? JSON.stringify(body) : undefined });
      return { status: r.status, body: await r.json().catch(() => ({})) };
    },
    async signout() {
      await fetch("/api/jace/signout", { method: "POST", credentials: "same-origin", headers: { "X-Jace-Passwords": "1" } });
    },
  });
  // No silent sign-in here: signing in with the computer's Jace account (Jace OS) is only for the
  // desktop app. The web app signs in when you press "Sign in with Jace".
  window.JPWeb = web;
})();
