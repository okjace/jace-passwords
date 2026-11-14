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

  // 2FA code fields: named plainly ("code", "token", "pin"…), or one-digit boxes in a row.
  const words = (el) => [el.name, el.id, el.placeholder, el.getAttribute("aria-label"), el.labels?.[0]?.textContent, el.className]
    .join(" ").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase().replace(/[^a-z0-9]+/g, " ");
  const OTP_WORDS = /(^| )(otp|totp|2fa|mfa|one time|onetime|verification|verify|authenticator|auth code|authcode|passcode|two factor|twofactor|2 step|2step|security code|token|tfa)( |$)/;
  const NOT_OTP = /(^| )(cvv|cvc|csc|card|zip|postal|post code|postcode|promo|coupon|discount|gift|referral|invite|phone|mobile|country|area|search|captcha)( |$)/;
  const shortNumeric = (el) => el.inputMode === "numeric" || el.type === "tel" || el.type === "number" || /\\d|\[0-9\]/.test(el.pattern || "")
    || (el.maxLength >= 4 && el.maxLength <= 10);
  const digitBoxes = (el) => {
    if (el.maxLength !== 1) return [];
    const scope = el.form || el.closest("div, fieldset, section") || document;
    return [...scope.querySelectorAll("input")].filter((i) => i.maxLength === 1 && visible(i) && !i.disabled);
  };
  function isOtpField(el, ac) {
    if (ac.includes("one-time-code")) return true;
    const w = words(el);
    if (NOT_OTP.test(w) || /cc-|card/.test(ac)) return false;
    if (OTP_WORDS.test(w)) return true;
    if (/(^| )(code|pin)( |$)/.test(w) && shortNumeric(el)) return true;
    return digitBoxes(el).length >= 4; // six one-digit boxes
  }
  // Put a code in a 2FA field, or spread it over one-digit boxes.
  function fillCode(el, code) {
    const boxes = digitBoxes(el);
    if (boxes.length >= 4) {
      const start = Math.max(0, boxes.indexOf(el));
      [...String(code)].forEach((d, n) => boxes[start + n] && setValue(boxes[start + n], d));
      return;
    }
    setValue(el, code);
  }

  // autocomplete="shipping address-line1" -> "address-line1" (ignores section-/shipping/billing/home… prefixes)
  const acKind = (el) => (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/)
    .filter((t) => t && !/^(section-.*|shipping|billing|home|work|mobile|fax|pager|on|off)$/.test(t)).pop() || "";
  const AC_MAP = { "cc-number": "cc-number", "cc-name": "cc-name", "cc-given-name": "cc-given", "cc-family-name": "cc-family",
    "cc-exp": "cc-exp", "cc-exp-month": "cc-exp-month", "cc-exp-year": "cc-exp-year", "cc-csc": "cc-csc", "cc-type": "cc-type",
    "given-name": "id-first", "additional-name": "id-middle", "family-name": "id-last", name: "id-name", email: "id-email",
    tel: "id-phone", "tel-national": "id-phone", "street-address": "id-address1", "address-line1": "id-address1",
    "address-line2": "id-address2", "address-line3": "id-address3", "address-level2": "id-city", "address-level1": "id-state",
    "postal-code": "id-zip", country: "id-country", "country-name": "id-country", organization: "id-company",
    bday: "id-birthday", "bday-day": "id-bday-day", "bday-month": "id-bday-month", "bday-year": "id-bday-year" };
  const loginContext = (el) => {
    const scope = el.form || document;
    return !!scope.querySelector("input[type=password]") || /login|signin|sign in|identifier/.test(words(el) + " " + location.pathname.toLowerCase());
  };
  const optionWords = (sel) => [...sel.options].slice(0, 40).map((o) => o.text.toLowerCase()).join(" ");

  function classify(el) {
    const isSelect = el instanceof HTMLSelectElement, isArea = el instanceof HTMLTextAreaElement;
    const isInput = el instanceof HTMLInputElement;
    const type = isInput ? (el.type || "text").toLowerCase() : "";
    const isRadio = type === "radio";
    const isText = isInput && ["text", "email", "password", "tel", "number", "search", ""].includes(type);
    if (!(isSelect || isArea || isRadio || isText) || el.disabled || el.readOnly) return null;
    const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
    const k = acKind(el);
    const w = words(el);
    if (isText && isOtpField(el, ac)) return "totp";
    if (k === "current-password") return "password";
    if (k === "new-password") return "new-password";
    if (k === "username" || k === "webauthn") return "username";
    if (AC_MAP[k]) return k === "email" && isText && loginContext(el) ? "username" : AC_MAP[k];
    if (type === "password") return /new|confirm|create|repeat|retype|signup|register/.test(hint(el)) ? "new-password" : "password";
    // ---- cards ----
    if (isRadio) return /(^| )(visa|mastercard|master card|amex|american express|discover|jcb|diners|maestro|credit|debit)( |$)/.test(w + " " + String(el.value).toLowerCase())
      && /card|payment|cc/.test(w + " " + (el.name || "").toLowerCase()) ? "cc-type" : null;
    if (/(^| )(card|cc|credit card|debit card) ?(number|num|no)( |$)|cardnumber|ccnumber|ccnum|cardnum/.test(w)) return "cc-number";
    if (/name on card|card ?holder|cardholder|(^| )cc ?name( |$)|card name/.test(w)) return "cc-name";
    if (/(^| )(cvv|cvv2|cvc|cvc2|csc|cvn|cid|card ?code|card ?security|security ?code)( |$)/.test(w)) return "cc-csc";
    if (/(card|cc|payment) ?(type|brand)|cardtype|cardbrand/.test(w) || (isSelect && /visa/.test(optionWords(el)) && /master ?card|amex|american express/.test(optionWords(el)))) return "cc-type";
    const expiry = /(^| )(exp|expiry|expiration|expires|valid thru|valid until|card ?exp)/.test(w);
    if (/(^| )(exp|expiry|expiration|cc|card)[a-z ]*(month|mm)( |$)|(^| )exp ?m( |$)/.test(w) || (isSelect && expiry && /january|jan|(^| )12( |$)/.test(optionWords(el)) && !/year/.test(w))) return "cc-exp-month";
    if (/(^| )(exp|expiry|expiration|cc|card)[a-z ]*(year|yy|yyyy)( |$)|(^| )exp ?y( |$)/.test(w) || (isSelect && expiry && /20[2-4][0-9]/.test(optionWords(el)))) return "cc-exp-year";
    if (expiry || /mm ?yy/.test(w)) return "cc-exp";
    // ---- logins ----
    if (isText && (type === "email" || /(^| )(user|username|login|email|e mail|account|identifier)( |$)/.test(w)) && loginContext(el)) return "username";
    // ---- addresses and contact details ----
    if (type === "email" || /(^| )(e ?mail|email address)( |$)/.test(w)) return "id-email";
    if (type === "tel" || /(^| )(phone|mobile|telephone|tel|cell|phone number|mobile number)( |$)/.test(w)) return "id-phone";
    if (/(^| )(first ?name|given ?name|fname|forename|first)( |$)/.test(w)) return "id-first";
    if (/(^| )(middle ?name|middle)( |$)/.test(w)) return "id-middle";
    if (/(^| )(last ?name|surname|family ?name|lname|last)( |$)/.test(w)) return "id-last";
    if (/(^| )(company|organi[sz]ation|business ?name|employer)( |$)/.test(w)) return "id-company";
    if (/(^| )(address ?(line)? ?2|addr2|apt|apartment|suite|unit|line2|address2)( |$)/.test(w)) return "id-address2";
    if (/(^| )(address ?(line)? ?3|line3|address3)( |$)/.test(w)) return "id-address3";
    if (/(^| )(address|street|address ?(line)? ?1|addr1|addr|line1|address1|street address)( |$)/.test(w)) return "id-address1";
    if (/(^| )(city|town|locality|suburb)( |$)/.test(w)) return "id-city";
    if (/(^| )(state|province|region|county|prefecture)( |$)/.test(w)) return "id-state";
    if (/(^| )(zip|zip ?code|postal|post ?code|postcode|postal ?code|pin ?code)( |$)/.test(w)) return "id-zip";
    if (/(^| )(country|nation)( |$)/.test(w)) return "id-country";
    if (/(^| )(birthday|birth ?date|date of birth|dob)( |$)/.test(w)) return "id-birthday";
    if (/(^| )(full ?name|your ?name|name)( |$)/.test(w) && !/user|company|card|account|login|file/.test(w)) return "id-name";
    return null;
  }

  const KIND_GROUP = (k) => k === "username" || k === "password" ? "login" : k === "new-password" ? "new" : k === "totp" ? "totp" : k.startsWith("cc-") ? "card" : k.startsWith("id-") ? "identity" : null;

  /* ---------- filling ---------- */
  function flash(el) {
    el.style.transition = "background-color .4s";
    const bg = el.style.backgroundColor;
    el.style.backgroundColor = "rgba(31,157,90,.12)";
    setTimeout(() => (el.style.backgroundColor = bg), 600);
  }
  function setValue(el, value) {
    if (value == null || value === "") return;
    el.focus();
    const proto = Object.getPrototypeOf(el);
    const setter = Object.getOwnPropertyDescriptor(proto, "value")?.set || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
    el.dispatchEvent(new Event("blur", { bubbles: true }));
    flash(el);
  }

  // ---- dropdowns ----
  const norm = (s) => String(s ?? "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, " ").trim();
  const MONTHS = ["january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "december"];
  function choose(sel, tests) {
    const opts = [...sel.options].filter((o) => !o.disabled && (o.value !== "" || o.text.trim() !== ""));
    for (const t of tests) {
      const o = opts.find((o) => t(norm(o.text), norm(o.value)));
      if (o) {
        sel.value = o.value; o.selected = true;
        sel.dispatchEvent(new Event("input", { bubbles: true }));
        sel.dispatchEvent(new Event("change", { bubbles: true }));
        flash(sel);
        return true;
      }
    }
    return false;
  }
  const num = (s) => (/^\d+$/.test(s) ? +s : NaN);
  function chooseMonth(sel, m) {
    m = +m;
    if (!m) return false;
    const name = MONTHS[m - 1], abbr = name.slice(0, 3);
    return choose(sel, [(t, v) => num(v) === m, (t) => num(t) === m, (t) => num(t.split(" ")[0]) === m,
      (t) => t === name || t === abbr, (t) => t.split(" ").includes(name) || t.split(" ").includes(abbr)]);
  }
  function chooseYear(sel, y) {
    y = String(y);
    if (!y) return false;
    const full = y.length === 2 ? "20" + y : y, short = full.slice(-2);
    return choose(sel, [(t, v) => v === full || t === full, (t, v) => v === short || t === short, (t) => t.endsWith(full)]);
  }
  const BRAND_WORDS = { Visa: ["visa"], Mastercard: ["mastercard", "master card", "mc"], Amex: ["amex", "american express"],
    Discover: ["discover"], JCB: ["jcb"], Diners: ["diners", "diners club"], Maestro: ["maestro"] };
  const cardBrand = (n) => { n = String(n || "").replace(/\D/g, ""); const p4 = +n.slice(0, 4) || 0;
    return n.startsWith("4") ? "Visa" : /^5[1-5]/.test(n) || (p4 >= 2221 && p4 <= 2720) ? "Mastercard" : /^3[47]/.test(n) ? "Amex"
      : /^(6011|65|64[4-9])/.test(n) ? "Discover" : p4 >= 3528 && p4 <= 3589 ? "JCB" : /^(36|30[0-5]|38)/.test(n) ? "Diners" : /^(50|5[6-8]|6)/.test(n) ? "Maestro" : ""; };
  function chooseCardType(sel, data) {
    const brand = data.brand || cardBrand(data.number);
    const words = BRAND_WORDS[brand] || [];
    const kind = data.cardType === "debit" ? "debit" : "credit";
    return choose(sel, [(t, v) => words.some((x) => t === x || v === x), (t, v) => words.some((x) => t.includes(x) || v.includes(x)),
      (t, v) => t.includes(kind) || v.includes(kind)]);
  }
  const COUNTRY_ALIASES = { "united states": ["us", "usa", "united states of america", "america"], "united kingdom": ["uk", "gb", "great britain", "britain", "england"] };
  let regionNames = null;
  try { regionNames = new Intl.DisplayNames(["en"], { type: "region" }); } catch { /* old browser */ }
  function countryNames(c) {
    const n = norm(c), out = new Set([n]);
    if (/^[a-z]{2}$/.test(n) && regionNames) { try { out.add(norm(regionNames.of(n.toUpperCase()))); } catch { /* */ } }
    for (const [name, al] of Object.entries(COUNTRY_ALIASES)) if (name === n || al.includes(n)) { out.add(name); al.forEach((a) => out.add(a)); }
    return out;
  }
  function chooseCountry(sel, country) {
    const want = countryNames(country);
    const nameOf = (code) => { try { return /^[a-z]{2}$/.test(code) && regionNames ? norm(regionNames.of(code.toUpperCase())) : ""; } catch { return ""; } };
    return choose(sel, [(t, v) => want.has(t) || want.has(v), (t, v) => want.has(nameOf(v)) || want.has(nameOf(t)), (t) => [...want].some((x) => x.length > 3 && t.startsWith(x))]);
  }
  const US_STATES = { al: "alabama", ak: "alaska", az: "arizona", ar: "arkansas", ca: "california", co: "colorado", ct: "connecticut", de: "delaware",
    dc: "district of columbia", fl: "florida", ga: "georgia", hi: "hawaii", id: "idaho", il: "illinois", in: "indiana", ia: "iowa", ks: "kansas",
    ky: "kentucky", la: "louisiana", me: "maine", md: "maryland", ma: "massachusetts", mi: "michigan", mn: "minnesota", ms: "mississippi",
    mo: "missouri", mt: "montana", ne: "nebraska", nv: "nevada", nh: "new hampshire", nj: "new jersey", nm: "new mexico", ny: "new york",
    nc: "north carolina", nd: "north dakota", oh: "ohio", ok: "oklahoma", or: "oregon", pa: "pennsylvania", ri: "rhode island", sc: "south carolina",
    sd: "south dakota", tn: "tennessee", tx: "texas", ut: "utah", vt: "vermont", va: "virginia", wa: "washington", wv: "west virginia",
    wi: "wisconsin", wy: "wyoming", pr: "puerto rico" };
  function chooseState(sel, state) {
    const n = norm(state), want = new Set([n]);
    if (US_STATES[n]) want.add(US_STATES[n]);
    for (const [code, name] of Object.entries(US_STATES)) if (name === n) want.add(code);
    return choose(sel, [(t, v) => want.has(t) || want.has(v), (t) => [...want].some((x) => x.length > 2 && t.startsWith(x))]);
  }
  function chooseText(sel, value) {
    const n = norm(value);
    return !!n && choose(sel, [(t, v) => t === n || v === n, (t) => t.startsWith(n)]);
  }
  function chooseRadio(el, data) {
    const group = el.name ? [...(el.form || document).querySelectorAll(`input[type=radio][name="${CSS.escape(el.name)}"]`)] : [el];
    const brand = data.brand || cardBrand(data.number), words = BRAND_WORDS[brand] || [];
    const kind = data.cardType === "debit" ? "debit" : "credit";
    const text = (r) => norm([r.value, r.id, r.getAttribute("aria-label"), r.labels?.[0]?.textContent].join(" "));
    const pick = group.find((r) => words.some((x) => text(r).split(" ").includes(x) || text(r).includes(x))) || group.find((r) => text(r).includes(kind));
    if (pick && !pick.checked) { pick.click(); flash(pick); return true; }
    return !!pick;
  }

  // ---- what goes in each kind of field ----
  function nameParts(full) {
    const p = String(full || "").trim().split(/\s+/).filter(Boolean);
    return { first: p[0] || "", middle: p.length > 2 ? p.slice(1, -1).join(" ") : "", last: p.length > 1 ? p[p.length - 1] : "" };
  }
  function valueFor(kind, data, el) {
    if (data.type === "card") {
      const y = String(data.expYear || ""), m = String(data.expMonth || "").replace(/^(\d)$/, "0$1");
      const yy = y.slice(-2), yyyy = y.length === 2 ? "20" + y : y;
      const ph = (el.placeholder || "").toLowerCase();
      const holder = nameParts(data.cardholder);
      return { "cc-number": data.number, "cc-name": data.cardholder, "cc-given": holder.first, "cc-family": holder.last, "cc-csc": data.cvv,
        "cc-exp-month": m, "cc-exp-year": el.maxLength === 2 || /^yy$/.test(ph) ? yy : yyyy,
        "cc-exp": m && y ? (/yyyy/.test(ph) || el.maxLength >= 7 ? `${m}/${yyyy}` : /\s\/\s/.test(ph) ? `${m} / ${yy}` : `${m}/${yy}`) : "" }[kind];
    }
    if (data.type === "identity" || data.type === "login") {
      const n = nameParts(data.fullName);
      const [by, bm, bd] = String(data.birthday || "").split("-");
      return { "id-first": data.firstName || n.first, "id-middle": data.middleName || n.middle, "id-last": data.lastName || n.last,
        "id-name": data.fullName || [data.firstName, data.lastName].filter(Boolean).join(" "), "id-email": data.email, "id-phone": data.phone,
        "id-address1": data.address1, "id-address2": data.address2, "id-address3": data.address3, "id-city": data.city, "id-state": data.state,
        "id-zip": data.zip, "id-country": data.country, "id-company": data.company, "id-birthday": data.birthday,
        "id-bday-day": bd, "id-bday-month": bm, "id-bday-year": by, username: data.email }[kind];
    }
    return null;
  }
  function fillField(el, kind, data) {
    if (el instanceof HTMLInputElement && el.type === "radio") return kind === "cc-type" && chooseRadio(el, data);
    if (el instanceof HTMLSelectElement) {
      if (kind === "cc-exp-month" || kind === "id-bday-month") return chooseMonth(el, kind === "cc-exp-month" ? data.expMonth : String(data.birthday || "").split("-")[1]);
      if (kind === "cc-exp-year" || kind === "id-bday-year") return chooseYear(el, kind === "cc-exp-year" ? data.expYear : String(data.birthday || "").split("-")[0]);
      if (kind === "cc-type") return chooseCardType(el, data);
      if (kind === "id-country") return chooseCountry(el, data.country);
      if (kind === "id-state") return chooseState(el, data.state);
      const v = valueFor(kind, data, el);
      return v ? chooseText(el, v) : false;
    }
    if (kind === "cc-type") return false;
    const v = valueFor(kind, data, el);
    if (!v) return false;
    setValue(el, v);
    return true;
  }

  function fieldsIn(scope) {
    return [...scope.querySelectorAll("input, select, textarea")]
      .filter((el) => (el instanceof HTMLInputElement && el.type === "radio") || visible(el))
      .map((el) => ({ el, kind: classify(el) })).filter((x) => x.kind);
  }

  function fill(data, anchor) {
    const group = data.type === "card" ? "card" : data.type === "identity" ? "identity" : null;
    let scope = anchor ? anchor.form || anchor.closest("form") || document : document;
    let fields = fieldsIn(scope);
    if (group && scope !== document && !fields.some((f) => KIND_GROUP(f.kind) === group)) fields = fieldsIn((scope = document));
    if (!fields.length && scope !== document) fields = fieldsIn(document);
    let did = false, otpDone = false;
    const radioGroups = new Set();
    for (const { el, kind } of fields) {
      if (data.type === "login") {
        let v = null;
        if (kind === "username") v = data.username;
        else if (kind === "password") v = data.password;
        else if (kind === "totp" && data.totp && !otpDone && !fields.some((f) => f.kind === "password")) { fillCode(el, data.totp); otpDone = did = true; continue; }
        if (v) { setValue(el, v); did = true; }
      } else if (data.type === "totp") {
        if (kind === "totp") { fillCode(el, data.code); did = true; break; }
      } else if (group && (KIND_GROUP(kind) === group || (group === "identity" && kind === "username"))) {
        if (el.type === "radio") { if (radioGroups.has(el.name)) continue; radioGroups.add(el.name); }
        if (fillField(el, kind, data)) did = true;
      }
    }
    return did;
  }

  // Frames that may receive a fill meant for the whole page: the page's own site, or a payment provider's.
  let lastNonce = null;
  const PAYMENT_HOSTS = /(^|\.)(stripe\.com|stripe\.network|braintreegateway\.com|braintree-api\.com|adyen\.com|adyenpayments\.com|checkout\.com|paypal\.com|paypalobjects\.com|squareup\.com|squarecdn\.com|recurly\.com|chargebee\.com|authorize\.net|worldpay\.com|mollie\.com|klarna\.com|razorpay\.com|paddle\.com|shopify\.com|shopifycs\.com|bluesnap\.com|cybersource\.com|globalpay\.com|spreedly\.com|vgs\.io|verygoodvault\.com|evervault\.com)$/;
  const siteOf = (host) => host.split(".").slice(-2).join(".");
  function frameMayFill(topOrigin, allowPayments) {
    if (window.top === window) return true;
    try {
      const top = new URL(topOrigin).hostname;
      return siteOf(top) === siteOf(location.hostname) || (allowPayments && PAYMENT_HOSTS.test(location.hostname));
    } catch { return false; }
  }

  /* ---------- UI (shadow DOM so pages can't restyle or read it easily) ---------- */
  const host = document.createElement("jace-passwords");
  const root = host.attachShadow({ mode: "closed" });
  root.innerHTML = `<style>
    :host { all: initial; }
    .icon { position: fixed; z-index: 2147483646; width: 22px; height: 22px; border: 0; padding: 3px; border-radius: 6px; background: transparent; cursor: pointer; display: none; }
    .icon:hover { background: rgba(109,93,252,.12); }
    .menu { position: fixed; z-index: 2147483647; width: 300px; max-width: calc(100vw - 16px); box-sizing: border-box; max-height: 340px; overflow: auto; overscroll-behavior: contain; background: #fff; color: #16181d; border: 1px solid #dfe2e7;
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
  let mailToken = 0;

  function attach() { if (!host.isConnected) document.documentElement.appendChild(host); }

  function placeIcon() {
    if (!current || !current.el.isConnected) { iconBtn.style.display = "none"; return; }
    const r = current.el.getBoundingClientRect();
    iconBtn.style.display = "block";
    iconBtn.style.left = `${r.right - 26}px`;
    iconBtn.style.top = `${r.top + (r.height - 22) / 2}px`;
    if (menu.style.display === "block") placeMenu();
  }
  // Below the field if it fits, else wherever there's more room; never taller than that room, so the
  // list scrolls instead of running off the window (short windows, small sign-in frames).
  function placeMenu() {
    const r = current.el.getBoundingClientRect();
    const vw = document.documentElement.clientWidth || innerWidth, vh = document.documentElement.clientHeight || innerHeight;
    const w = Math.min(300, vw - 16);
    menu.style.left = `${Math.max(8, Math.min(r.left, vw - w - 8))}px`;
    const below = vh - r.bottom - 14, above = r.top - 14;
    menu.style.maxHeight = "none";
    const want = Math.min(menu.scrollHeight || 120, 340);
    const down = below >= want || below >= above;
    const room = Math.max(96, Math.min(340, down ? below : above));
    const h = Math.min(want, room);
    menu.style.maxHeight = `${room}px`;
    const top = down ? r.bottom + 6 : r.top - h - 6;
    menu.style.top = `${Math.max(4, Math.min(top, vh - h - 4))}px`;
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
      html += `<div id="jp-mail"><div class="msg" style="font-size:12px">✉ Checking your email for a code…</div></div>`;
      const token = (mailToken = Math.random());
      send({ type: "email-codes" }).then((mail) => {
        const slot = root.getElementById("jp-mail");
        if (!slot || token !== mailToken) return;
        slot.innerHTML = (mail.codes || []).map((c) => `<button class="it" data-code="${esc(c.code)}"><span class="tile" style="background:#d93f3f">✉</span><span class="m"><div class="t">${esc(c.code)} · from ${esc(c.provider)}</div><div class="muted">${esc(c.from)}</div></span></button>`).join("")
          || `<div class="msg" style="font-size:12px">${mail.checked ? "No code in your newest emails yet. Open this menu again when it arrives." : "Emailed a code? Turn on your email in the Jace Passwords toolbar button (✉ Email codes), or open your inbox in a tab."}</div>`;
        placeMenu();
      });
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
    if (it.dataset.code) { fillCode(anchor, it.dataset.code); hideMenu(); return; }
    if (it.dataset.totp && !it.dataset.id) {
      const r = await send({ type: "totp-for-tab" });
      if (r.totp) fillCode(anchor, r.totp);
      else menu.innerHTML = `<div class="msg">No recent login with a 2FA code on this tab.</div>`;
      if (r.totp) hideMenu();
      return;
    }
    if (it.dataset.sso) { hideMenu(); return; }
    const data = await send({ type: "fill", id: it.dataset.id });
    if (data.error) { menu.innerHTML = `<div class="msg">${esc(data.message)}</div>`; return; }
    if (it.dataset.totpId) { if (data.totp) fillCode(anchor, data.totp); }
    else {
      fill(data, anchor);
      // Card and address fields can sit in other frames (e.g. Stripe puts each card field in its own).
      if (data.type === "card" || data.type === "identity") {
        lastNonce = Math.random().toString(36).slice(2);
        send({ type: "fill-frames", data, nonce: lastNonce });
      }
    }
    hideMenu();
  });

  iconBtn.addEventListener("mousedown", (e) => e.preventDefault());
  iconBtn.addEventListener("click", (e) => { e.preventDefault(); menu.style.display === "block" ? hideMenu() : openMenu(); });

  document.addEventListener("focusin", (e) => {
    const el = e.composedPath()[0];
    if (el === host) return;
    const kind = el instanceof HTMLInputElement ? classify(el) : null;
    if (!kind) { if (!host.contains(el)) { current = null; hideMenu(); placeIcon(); } return; }
    const first = current?.el !== el;
    current = { el, kind };
    attach();
    placeIcon();
    if (kind === "totp" && first && !el.value) openMenu(); // offer the code right away
  }, true);
  document.addEventListener("mousedown", (e) => { if (!e.composedPath().includes(host) && e.target !== current?.el) hideMenu(); }, true);
  addEventListener("scroll", placeIcon, true);
  addEventListener("resize", placeIcon);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hideMenu();
    if (e.key === "ArrowDown" && current && e.target === current.el && e.altKey) { e.preventDefault(); openMenu(); }
  }, true);

  /* ---------- sign-in codes from your inbox (Gmail, Outlook, Proton Mail tabs) ---------- */
  // When a site emails you a code, the 2FA menu offers it. Jace Passwords reads it from your inbox tab in this
  // browser, only when you open that menu; nothing is sent anywhere and no email password is needed.
  const MAIL = { "mail.google.com": "Gmail", "outlook.live.com": "Outlook", "outlook.office.com": "Outlook",
    "outlook.office365.com": "Outlook", "mail.proton.me": "Proton Mail" };
  const { codesIn } = globalThis.JPMail;
  function scanMail(siteName) {
    const provider = MAIL[location.hostname];
    if (!provider || window !== window.top) return { codes: [], rows: 0 };
    const txt = (el) => (el?.innerText || el?.getAttribute?.("aria-label") || "").trim();
    const shown = (el) => el.getClientRects().length > 0;
    const out = [];
    const add = (text, label, n, unread) => {
      for (const code of codesIn(text)) {
        const site = siteName && text.toLowerCase().includes(siteName) ? 1 : 0;
        out.push({ code, provider, from: label.replace(/\s+/g, " ").trim().slice(0, 70), score: site * 4 + (unread ? 2 : 0) + (8 - Math.min(n, 8)) / 4 });
      }
    };
    // the message you have open (Proton shows it in a same-origin frame)
    const bodies = [...document.querySelectorAll(".a3s, [aria-label='Message body'], div[role='document'], [data-testid='message-content:body'], .message-content")].filter(shown);
    for (const f of document.querySelectorAll("iframe")) { try { const b = f.contentDocument?.body; if (b && shown(f)) bodies.push(b); } catch { /* other site's frame */ } }
    const subject = txt(document.querySelector("h2.hP, [data-testid='message-header-expanded:subject'], [data-testid='conversation-header:subject'], [role='heading'][aria-level='2']"));
    bodies.slice(-3).forEach((b) => add(txt(b), subject || "Open message", 0, true));
    // the newest messages in the list
    const rows = [...document.querySelectorAll("tr.zA, [role='listbox'] [role='option'], [data-shortcut-target='item-container'], .item-container")].filter(shown).slice(0, 8);
    rows.forEach((r, n) => {
      const unread = r.classList.contains("zE") || /unread/i.test(r.className + " " + (r.getAttribute("aria-label") || ""));
      const label = txt(r.querySelector(".bog, [data-testid='message-row:subject'], [title]")) || txt(r).split("\n").slice(0, 2).join(" · ");
      add(txt(r) + " " + (r.getAttribute("aria-label") || ""), label, n, unread);
    });
    const best = {};
    for (const c of out) if (!best[c.code] || best[c.code].score < c.score) best[c.code] = c;
    return { codes: Object.values(best).sort((a, b) => b.score - a.score).slice(0, 3), rows: rows.length + bodies.length, host: location.hostname };
  }
  if (MAIL[location.hostname] && window === window.top) {
    B.runtime.onMessage.addListener((msg, _sender, reply) => {
      if (msg.type !== "email-codes-scan") return;
      try { reply(scanMail(msg.siteName || "")); } catch { reply({ codes: [], rows: 0 }); }
    });
  }

  /* ---------- messages from the popup / background ---------- */
  B.runtime.onMessage.addListener((msg) => {
    if (msg.type === "do-fill") {
      if (msg.nonce) { // a fill sent to every frame of the page
        if (msg.nonce === lastNonce) return;                       // the frame it came from already filled
        if (!frameMayFill(msg.topOrigin, msg.data.type !== "login")) return; // ads and other third parties never get it
        fill(msg.data, msg.data.type === "login" ? current?.el || document.querySelector("input[type=password]") : null);
        return;
      }
      const anchor = current?.el || (msg.data.type === "login" ? document.querySelector("input[type=password]") || document.querySelector("input") : null);
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
  // Cards, addresses, email and phone typed into a form, to offer saving them (never the CVC).
  const ID_FIELD = { "id-first": "firstName", "id-middle": "middleName", "id-last": "lastName", "id-name": "fullName", "id-email": "email",
    "id-phone": "phone", "id-address1": "address1", "id-address2": "address2", "id-address3": "address3", "id-city": "city", "id-state": "state",
    "id-zip": "zip", "id-country": "country", "id-company": "company", "id-birthday": "birthday" };
  const luhn = (n) => { const d = [...n].map(Number).reverse(); return d.length >= 12 && d.length <= 19 && d.reduce((t, x, i) => t + (i % 2 ? (x * 2 > 9 ? x * 2 - 9 : x * 2) : x), 0) % 10 === 0; };
  const shownValue = (el) => (el instanceof HTMLSelectElement ? (el.selectedOptions[0]?.value ? el.selectedOptions[0].text.trim() : "") : String(el.value || "").trim());
  function captureItems(scope) {
    const fields = fieldsIn(scope);
    const card = {}, ident = {};
    for (const { el, kind } of fields) {
      const v = shownValue(el);
      if (!v) continue;
      if (kind === "cc-number") card.number = v.replace(/\D/g, "");
      else if (kind === "cc-name") card.cardholder = v;
      else if (kind === "cc-given") card.first = v;
      else if (kind === "cc-family") card.last = v;
      else if (kind === "cc-exp") { const m = v.match(/(\d{1,2})\s*[\/\-.]?\s*(\d{2,4})/); if (m) { card.expMonth = m[1].padStart(2, "0"); card.expYear = m[2].length === 2 ? "20" + m[2] : m[2]; } }
      else if (kind === "cc-exp-month") { const n = +String(el.value).replace(/\D/g, "") || MONTHS.findIndex((x) => norm(v).startsWith(x.slice(0, 3))) + 1; if (n >= 1 && n <= 12) card.expMonth = String(n).padStart(2, "0"); }
      else if (kind === "cc-exp-year") { const y = v.replace(/\D/g, ""); card.expYear = y.length === 2 ? "20" + y : y; }
      else if (ID_FIELD[kind] && !ident[ID_FIELD[kind]]) ident[ID_FIELD[kind]] = v;
    }
    if (!card.cardholder && (card.first || card.last)) card.cardholder = [card.first, card.last].filter(Boolean).join(" ");
    delete card.first; delete card.last;
    const out = { url: location.href };
    if (card.number && luhn(card.number)) out.card = card;
    if (!ident.fullName && (ident.firstName || ident.lastName)) ident.fullName = [ident.firstName, ident.middleName, ident.lastName].filter(Boolean).join(" ");
    const hasPassword = !!scope.querySelector?.("input[type=password]");
    if (!hasPassword && Object.keys(ident).length >= 2 && (ident.address1 || ident.phone || ident.email)) out.identity = ident;
    if (out.card || out.identity) send({ type: "submitted-items", ...out });
  }

  function capture(form) {
    const scope = form || document;
    try { captureItems(scope); } catch { /* never break the page's submit */ }
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
    if (p.none || !p.status) return maybeOfferItem();
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
      maybeOfferItem();
    });
    setTimeout(() => (slot.innerHTML = ""), 30000);
  }

  async function maybeOfferItem() {
    const p = await send({ type: "pending-item" });
    if (!p.status) return;
    attach();
    const slot = root.querySelector(".slot");
    const what = p.type === "card" ? "card" : "address and contact details";
    slot.innerHTML = `<div class="banner"><div class="hd" style="padding:0 0 6px">${ICON} Jace Passwords</div>
      <b>${p.status === "update" ? `Update your saved ${what}?` : `Save this ${what} for next time?`}</b>
      <div class="muted" style="margin-top:4px;white-space:normal">${esc(p.summary || p.title || "")}</div>
      <div class="row"><button class="btn" data-s="save">${p.status === "update" ? "Update" : "Save"}</button><button class="btn sec" data-s="later">Not now</button></div></div>`;
    slot.querySelector(".banner").addEventListener("click", async (e) => {
      const s = e.target.dataset.s;
      if (!s) return;
      await send({ type: "save-item-pending", save: s === "save", itemType: p.type });
      slot.innerHTML = "";
      maybeOfferItem(); // a card and an address from the same checkout: one after the other
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
