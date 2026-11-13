"use strict";
/* Import from other password managers, in the app window (desktop app and web app alike).
 * The file is read here and turned into Jace Passwords items; the vault saves them
 * (POST /api/import-items). Passkeys keep working: their P-256 private keys move with them.
 *
 *   Bitwarden          .json (unencrypted)      logins, 2FA, passkeys, cards, notes, identities
 *   Credential Exchange (CXF) .json             logins, 2FA, passkeys, cards, notes
 *   Proton Pass        .zip or .json            logins, 2FA, cards, notes, identities (not passkeys:
 *                                               Proton exports them in its own format)
 *   1Password          .1pux                    logins, 2FA, cards, notes, identities (1Password
 *                                               doesn't export passkeys)
 *   CSV                Chrome, Firefox, Safari, Edge, LastPass, Dashlane…  (parsed by the vault)
 */
(() => {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64e = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const b64any = (s) => { s = String(s || "").replace(/-/g, "+").replace(/_/g, "/").replace(/\s/g, ""); return Uint8Array.from(atob(s + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)); };
  const b64u = (u8) => b64e(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const str = (v) => (v === undefined || v === null ? "" : String(v));
  const clean = (o) => Object.fromEntries(Object.entries(o).filter(([, v]) => v !== "" && v !== undefined && v !== null && !(Array.isArray(v) && !v.length)));

  // ---------- zip (store / deflate) ----------
  async function unzip(buf) {
    const u8 = new Uint8Array(buf), dv = new DataView(buf);
    let eocd = -1;
    for (let i = u8.length - 22; i >= Math.max(0, u8.length - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error("That isn't a zip file.");
    const count = dv.getUint16(eocd + 10, true);
    let p = dv.getUint32(eocd + 16, true);
    const files = {};
    for (let n = 0; n < count; n++) {
      const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true);
      const nameLen = dv.getUint16(p + 28, true), extraLen = dv.getUint16(p + 30, true), commentLen = dv.getUint16(p + 32, true);
      const local = dv.getUint32(p + 42, true);
      const name = dec.decode(u8.subarray(p + 46, p + 46 + nameLen));
      const start = local + 30 + dv.getUint16(local + 26, true) + dv.getUint16(local + 28, true);
      const data = u8.subarray(start, start + csize);
      files[name] = { method, data };
      p += 46 + nameLen + extraLen + commentLen;
    }
    return {
      names: Object.keys(files),
      async text(name) {
        const f = files[name];
        if (!f) return null;
        if (f.method === 0) return dec.decode(f.data);
        if (f.method !== 8) throw new Error("This zip uses a compression Jace Passwords can't read.");
        const stream = new Blob([f.data]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
        return dec.decode(new Uint8Array(await new Response(stream).arrayBuffer()));
      },
    };
  }

  // ---------- passkeys ----------
  const stats = () => ({ items: 0, passkeys: 0, skippedPasskeys: 0, notes: [] });
  async function passkey(p, st) {
    try {
      const key = b64any(p.key);
      await crypto.subtle.importKey("pkcs8", key, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]); // must be P-256 (ES256)
      st.passkeys++;
      return { credentialId: b64u(p.credentialId), rpId: str(p.rpId).toLowerCase(), userHandle: p.userHandle ? b64u(p.userHandle) : "",
        userName: str(p.userName), userDisplayName: str(p.userDisplayName), alg: -7, privateKey: b64e(key),
        createdAt: p.createdAt || new Date().toISOString(), importedFrom: p.from };
    } catch {
      st.skippedPasskeys++;
      return null;
    }
  }
  const guidBytes = (id) => {
    id = str(id);
    if (id.startsWith("b64.")) return b64any(id.slice(4));
    const hex = id.replace(/-/g, "");
    return /^[0-9a-f]{32}$/i.test(hex) ? Uint8Array.from(hex.match(/../g).map((h) => parseInt(h, 16))) : b64any(id);
  };

  // ---------- Bitwarden ----------
  async function bitwarden(j, st) {
    if (j.encrypted) throw new Error("This Bitwarden export is encrypted. In Bitwarden, export again as \"JSON\" (not \"JSON (Encrypted)\").");
    const folders = Object.fromEntries((j.folders || []).map((f) => [f.id, f.name]));
    const out = [];
    for (const it of j.items || []) {
      const tags = it.folderId && folders[it.folderId] ? [folders[it.folderId]] : [];
      const custom = (it.fields || []).map((f) => ({ label: str(f.name), value: str(f.value), hidden: f.type === 1 })).filter((f) => f.label || f.value);
      const base = { title: str(it.name) || "Untitled", favorite: !!it.favorite, tags };
      if (it.type === 1) {
        const l = it.login || {};
        const passkeys = [];
        for (const c of l.fido2Credentials || []) {
          if (c.keyAlgorithm && c.keyAlgorithm !== "ECDSA" || c.keyCurve && c.keyCurve !== "P-256") { st.skippedPasskeys++; continue; }
          const pk = await passkey({ credentialId: guidBytes(c.credentialId), rpId: c.rpId, userHandle: c.userHandle ? b64any(c.userHandle) : null,
            userName: c.userName, userDisplayName: c.userDisplayName, key: c.keyValue, createdAt: c.creationDate, from: "Bitwarden" }, st);
          if (pk) passkeys.push(pk);
        }
        out.push({ ...base, type: "login", fields: clean({ username: str(l.username), password: str(l.password), totp: str(l.totp),
          urls: (l.uris || []).map((u) => str(u.uri)).filter(Boolean), notes: str(it.notes), custom, passkeys }) });
      } else if (it.type === 2) {
        out.push({ ...base, type: "note", fields: clean({ body: str(it.notes), custom }) });
      } else if (it.type === 3) {
        const c = it.card || {};
        out.push({ ...base, type: "card", fields: clean({ cardholder: str(c.cardholderName), number: str(c.number).replace(/\D/g, ""), brand: str(c.brand),
          expMonth: str(c.expMonth).padStart(2, "0").replace(/^00$/, ""), expYear: str(c.expYear), cvv: str(c.code), notes: str(it.notes), custom }) });
      } else if (it.type === 4) {
        const d = it.identity || {};
        out.push({ ...base, type: "identity", fields: clean({ fullName: [d.firstName, d.middleName, d.lastName].filter(Boolean).join(" "),
          firstName: str(d.firstName), lastName: str(d.lastName), email: str(d.email), phone: str(d.phone), company: str(d.company),
          address1: str(d.address1), address2: [d.address2, d.address3].filter(Boolean).join(", "), city: str(d.city), state: str(d.state),
          zip: str(d.postalCode), country: str(d.country), notes: str(it.notes), custom }) });
      }
    }
    return out;
  }

  // ---------- FIDO Credential Exchange Format ----------
  const cxfVal = (v) => (v && typeof v === "object" && "value" in v ? str(v.value) : str(v));
  async function cxf(j, st) {
    const out = [];
    for (const acct of j.accounts || []) {
      for (const it of acct.items || []) {
        const creds = it.credentials || [];
        const urls = (it.scope?.urls || []).map(str).filter(Boolean);
        const login = { username: "", password: "", urls, totp: "", passkeys: [] };
        let isLogin = false;
        for (const c of creds) {
          if (c.type === "basic-auth") { isLogin = true; login.username = cxfVal(c.username); login.password = cxfVal(c.password); }
          else if (c.type === "totp") {
            isLogin = true;
            const q = new URLSearchParams({ secret: str(c.secret), digits: str(c.digits || 6), period: str(c.period || 30), algorithm: str(c.algorithm || "sha1").toUpperCase() });
            if (c.issuer) q.set("issuer", c.issuer);
            login.totp = `otpauth://totp/${encodeURIComponent(str(c.issuer || it.title))}?${q}`;
          } else if (c.type === "passkey") {
            isLogin = true;
            const pk = await passkey({ credentialId: b64any(c.credentialId), rpId: c.rpId, userHandle: c.userHandle ? b64any(c.userHandle) : null,
              userName: c.username, userDisplayName: c.userDisplayName, key: c.key, from: "Credential Exchange" }, st);
            if (pk) { login.passkeys.push(pk); if (!login.username) login.username = str(c.username); if (!urls.length && c.rpId) urls.push("https://" + c.rpId); }
          } else if (c.type === "note") out.push({ type: "note", title: str(it.title) || "Note", fields: { body: cxfVal(c.content) } });
          else if (c.type === "credit-card") {
            const exp = cxfVal(c.expiryDate);
            out.push({ type: "card", title: str(it.title) || "Card", fields: clean({ cardholder: cxfVal(c.fullName), number: cxfVal(c.number).replace(/\D/g, ""),
              cvv: cxfVal(c.verificationNumber), pin: cxfVal(c.pin), expYear: exp.slice(0, 4), expMonth: exp.slice(5, 7) }) });
          }
        }
        if (isLogin) out.push({ type: "login", title: str(it.title) || urls[0] || "Login", fields: clean(login) });
      }
    }
    return out;
  }

  // ---------- Proton Pass ----------
  function proton(j, st) {
    if (j.encrypted) throw new Error("This Proton Pass export is encrypted. Export again without a passphrase (PGP).");
    const out = [];
    for (const vault of Object.values(j.vaults || {})) {
      for (const it of vault.items || []) {
        const d = it.data || {}, c = d.content || {}, meta = d.metadata || {};
        const custom = (d.extraFields || []).map((f) => ({ label: str(f.fieldName), value: str(f.data?.content ?? f.data?.totpUri), hidden: f.type === "hidden" }));
        const base = { title: str(meta.name) || "Untitled", favorite: !!it.pinned };
        if (d.type === "login") {
          if ((c.passkeys || []).length) { st.skippedPasskeys += c.passkeys.length; }
          out.push({ ...base, type: "login", fields: clean({ username: str(c.itemUsername || c.itemEmail || c.username), password: str(c.password),
            urls: (c.urls || []).map(str), totp: str(c.totpUri), notes: str(meta.note), custom }) });
        } else if (d.type === "note") out.push({ ...base, type: "note", fields: clean({ body: str(meta.note), custom }) });
        else if (d.type === "creditCard") {
          const exp = str(c.expirationDate); // "YYYY-MM" or "MMYYYY"
          const [y, m] = exp.includes("-") ? exp.split("-") : [exp.slice(2), exp.slice(0, 2)];
          out.push({ ...base, type: "card", fields: clean({ cardholder: str(c.cardholderName), number: str(c.number).replace(/\D/g, ""), cvv: str(c.verificationNumber),
            pin: str(c.pin), expMonth: m, expYear: y, notes: str(meta.note), custom }) });
        } else if (d.type === "identity") {
          out.push({ ...base, type: "identity", fields: clean({ fullName: str(c.fullName), email: str(c.email), phone: str(c.phoneNumber), company: str(c.company),
            address1: str(c.streetAddress), city: str(c.city), state: str(c.stateOrProvince), zip: str(c.zipOrPostalCode), country: str(c.countryOrRegion),
            birthday: str(c.birthdate), notes: str(meta.note), custom }) });
        } else if (d.type === "alias") out.push({ ...base, type: "alias", fields: clean({ alias: str(it.aliasEmail), notes: str(meta.note) }) });
      }
    }
    return out;
  }

  // ---------- 1Password (.1pux) ----------
  function onePassword(j) {
    const out = [];
    for (const acct of j.accounts || []) for (const vault of acct.vaults || []) for (const it of vault.items || []) {
      if (it.state === "archived" || it.trashed) continue;
      const o = it.overview || {}, d = it.details || {};
      const fields = { notes: str(d.notesPlain), custom: [] };
      let totp = "";
      const sectionVal = (v) => v.string ?? v.concealed ?? v.email?.email_address ?? v.phone ?? v.url ?? v.creditCardNumber ?? v.creditCardType ?? v.monthYear ?? v.date ?? v.totp ?? "";
      for (const s of d.sections || []) for (const f of s.fields || []) {
        const v = f.value || {};
        if (v.totp) { totp ||= v.totp; continue; }
        const val = str(sectionVal(v));
        if (val) fields.custom.push({ label: str(f.title || f.id), value: val, hidden: "concealed" in v });
      }
      const base = { title: str(o.title) || "Untitled", tags: o.tags || [], favorite: !!it.favIndex };
      const cat = str(it.categoryUuid);
      if (cat === "001" || cat === "005") {
        const lf = d.loginFields || [];
        const user = lf.find((f) => f.designation === "username")?.value || "";
        const pw = lf.find((f) => f.designation === "password")?.value || d.password || "";
        const urls = [...(o.urls || []).map((u) => str(u.url)), str(o.url)].filter(Boolean);
        out.push({ ...base, type: "login", fields: clean({ ...fields, username: str(user), password: str(pw), urls: [...new Set(urls)], totp }) });
      } else if (cat === "003") out.push({ ...base, type: "note", fields: clean({ body: fields.notes, custom: fields.custom }) });
      else if (cat === "002") {
        const get = (label) => fields.custom.find((f) => f.label.toLowerCase().includes(label))?.value || "";
        const exp = get("expir");
        out.push({ ...base, type: "card", fields: clean({ cardholder: get("cardholder") || get("name"), number: get("number").replace(/\D/g, ""), cvv: get("verification") || get("cvv"),
          pin: get("pin"), expYear: exp.slice(0, 4), expMonth: exp.slice(4, 6), notes: fields.notes, custom: fields.custom }) });
      } else if (cat === "004") out.push({ ...base, type: "identity", fields: clean({ fullName: str(o.title), notes: fields.notes, custom: fields.custom }) });
    }
    return out;
  }

  // ---------- entry point ----------
  // -> { csv } for CSV files (the vault parses those), or { items, stats } for everything else.
  async function readExport(file) {
    const st = stats();
    const name = file.name.toLowerCase();
    if (name.endsWith(".csv")) return { csv: await file.text() };
    const buf = await file.arrayBuffer();
    const u8 = new Uint8Array(buf);
    if (u8[0] === 0x50 && u8[1] === 0x4b) { // zip: 1Password .1pux or Proton Pass
      const z = await unzip(buf);
      const onepux = z.names.find((n) => /(^|\/)export\.data$/.test(n));
      if (onepux) { const items = onePassword(JSON.parse(await z.text(onepux))); return { items, stats: { ...st, items: items.length } }; }
      const pp = z.names.find((n) => /data\.json$/.test(n));
      if (pp) { const items = proton(JSON.parse(await z.text(pp)), st); return { items, stats: { ...st, items: items.length } }; }
      throw new Error("That zip isn't a 1Password (.1pux) or Proton Pass export.");
    }
    let j;
    try { j = JSON.parse(dec.decode(u8)); } catch { throw new Error("Jace Passwords can't read that file. Use a CSV, JSON, Proton Pass zip or 1Password .1pux export."); }
    let items;
    if (Array.isArray(j.items) && ("encrypted" in j || "folders" in j)) items = await bitwarden(j, st);
    else if (Array.isArray(j.accounts) && (j.exporterRpId || j.exporterDisplayName || j.version)) items = await cxf(j, st);
    else if (j.vaults && typeof j.vaults === "object") items = proton(j, st);
    else if (j.format === "jace-passwords/1") throw new Error("That's a Jace Passwords backup: it's encrypted with its own password, so open it in Jace Passwords instead of importing it.");
    else throw new Error("Jace Passwords doesn't recognize that JSON export.");
    return { items, stats: { ...st, items: items.length } };
  }

  globalThis.JPImport = { readExport, _unzip: unzip };
})();
