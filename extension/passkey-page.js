/* Jace Passwords — passkeys. Runs in the page's own world (so the site's
 * navigator.credentials is the one we wrap). It only forwards requests to the
 * extension's content script; the extension checks the page's real origin and
 * your vault signs. "Use another device" falls back to the browser's own. */
(() => {
  if (!window.isSecureContext || !navigator.credentials || window.__jacePasskeys) return;
  Object.defineProperty(window, "__jacePasskeys", { value: true });

  const native = {
    create: navigator.credentials.create.bind(navigator.credentials),
    get: navigator.credentials.get.bind(navigator.credentials),
  };
  const TAG = "jace-passwords-passkey";
  const pending = new Map();
  let seq = 0;

  const toB64u = (buf) => {
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const fromB64u = (s) => {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };

  window.addEventListener("message", (e) => {
    if (e.source !== window || e.data?.tag !== TAG || e.data.dir !== "to-page") return;
    const p = pending.get(e.data.id);
    if (!p) return;
    pending.delete(e.data.id);
    p(e.data.result);
  });

  function ask(kind, req, signal) {
    return new Promise((resolve, reject) => {
      const id = ++seq + "-" + Math.random().toString(36).slice(2);
      pending.set(id, resolve);
      if (signal) {
        if (signal.aborted) { pending.delete(id); return reject(new DOMException("The operation was aborted.", "AbortError")); }
        signal.addEventListener("abort", () => {
          if (!pending.has(id)) return;
          pending.delete(id);
          window.postMessage({ tag: TAG, dir: "to-ext", id, kind: "abort" }, location.origin);
          reject(new DOMException("The operation was aborted.", "AbortError"));
        }, { once: true });
      }
      window.postMessage({ tag: TAG, dir: "to-ext", id, kind, req }, location.origin);
    });
  }

  function own(obj, props) {
    for (const [k, v] of Object.entries(props)) Object.defineProperty(obj, k, { value: v, enumerable: true, configurable: true });
    return obj;
  }

  function credential(r, isCreate, extensions) {
    const proto = isCreate ? window.AuthenticatorAttestationResponse?.prototype : window.AuthenticatorAssertionResponse?.prototype;
    const response = Object.create(proto || Object.prototype);
    const clientDataJSON = fromB64u(r.clientDataJSON);
    if (isCreate) {
      const authData = fromB64u(r.authenticatorData), pub = fromB64u(r.publicKey);
      own(response, {
        clientDataJSON, attestationObject: fromB64u(r.attestationObject),
        getTransports: () => r.transports.slice(), getAuthenticatorData: () => authData,
        getPublicKey: () => pub, getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
      });
    } else {
      own(response, {
        clientDataJSON, authenticatorData: fromB64u(r.authenticatorData),
        signature: fromB64u(r.signature), userHandle: r.userHandle ? fromB64u(r.userHandle) : null,
      });
    }
    const results = {};
    if (extensions?.credProps) results.credProps = { rk: true };
    const cred = Object.create(window.PublicKeyCredential?.prototype || Object.prototype);
    own(cred, {
      id: r.credentialId, rawId: fromB64u(r.credentialId), type: "public-key", response,
      authenticatorAttachment: "platform", getClientExtensionResults: () => ({ ...results }),
      toJSON: () => ({
        id: r.credentialId, rawId: r.credentialId, type: "public-key", authenticatorAttachment: "platform",
        clientExtensionResults: results,
        response: isCreate
          ? { clientDataJSON: r.clientDataJSON, attestationObject: r.attestationObject, authenticatorData: r.authenticatorData,
              transports: r.transports, publicKey: r.publicKey, publicKeyAlgorithm: r.publicKeyAlgorithm }
          : { clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData, signature: r.signature, userHandle: r.userHandle || null },
      }),
    });
    return cred;
  }

  navigator.credentials.create = async function (options) {
    const pk = options?.publicKey;
    if (!pk) return native.create(options);
    const req = {
      challenge: toB64u(pk.challenge),
      rp: { id: pk.rp?.id || location.hostname, name: pk.rp?.name || "" },
      user: { id: toB64u(pk.user.id), name: pk.user.name || "", displayName: pk.user.displayName || "" },
      algs: (pk.pubKeyCredParams || []).map((p) => p.alg),
      exclude: (pk.excludeCredentials || []).map((c) => toB64u(c.id)),
    };
    const r = await ask("create", req, options.signal);
    if (r.fallback) return native.create(options);
    if (r.error) throw new DOMException(r.message || "Not allowed.", r.error);
    return credential(r, true, pk.extensions);
  };

  navigator.credentials.get = async function (options) {
    const pk = options?.publicKey;
    if (!pk) return native.get(options);
    const req = {
      challenge: toB64u(pk.challenge),
      rpId: pk.rpId || location.hostname,
      allow: (pk.allowCredentials || []).map((c) => toB64u(c.id)),
      conditional: options.mediation === "conditional",
    };
    const r = await ask("get", req, options.signal);
    if (r.fallback) return native.get(options);
    if (r.error) throw new DOMException(r.message || "Not allowed.", r.error);
    return credential(r, false, pk.extensions);
  };

  // Sites offer "create a passkey" / passkey autofill only when these say yes.
  if (window.PublicKeyCredential) {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    PublicKeyCredential.isConditionalMediationAvailable = async () => true;
  }
})();
