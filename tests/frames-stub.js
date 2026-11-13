// Stand-in for the extension runtime in the frame tests (tests/frames-test.html): every frame's
// content.js registers its message listener here; a "fill-frames" request is delivered to every
// frame of the page, the way the real background.js does with tabs.sendMessage.
(() => {
  const listeners = [];
  window.__jpDeliver = (msg) => listeners.forEach((l) => l(msg, {}, () => {}));
  window.addEventListener("message", (e) => { if (e.data?.__jptest === "do-fill") window.__jpDeliver(e.data.msg); });
  const card = { type: "card", cardholder: "Jace Tester", number: "4111111111111111", expMonth: "09", expYear: "2029", cvv: "123", brand: "Visa", cardType: "credit" };
  window.chrome = { runtime: { onMessage: { addListener: (l) => listeners.push(l) }, sendMessage(msg, cb) {
    let r = { none: true };
    if (msg.type === "status") r = { locked: false };
    if (msg.type === "match") r = { site: "test", logins: [], cards: [{ id: "C1", type: "card", title: "Test Visa", last4: "1111", brand: "Visa" }], identities: [] };
    if (msg.type === "fill") r = card;
    if (msg.type === "fill-frames") {
      const out = { type: "do-fill", data: msg.data, nonce: msg.nonce, topOrigin: window.top.location.origin };
      window.__jpDeliver(out);
      for (let i = 0; i < window.frames.length; i++) window.frames[i].postMessage({ __jptest: "do-fill", msg: out }, "*");
      r = { ok: true };
    }
    setTimeout(() => cb(r), 5);
  } } };
  // Report this frame's field values when asked (for the cross-site frame the test can't read).
  window.addEventListener("message", (e) => {
    if (e.data === "jp-values?") e.source.postMessage({ jpValues: [...document.querySelectorAll("input")].map((i) => i.name + "=" + i.value) }, "*");
  });
})();
(async () => { (0, eval)(await fetch("/extension/content.js").then((r) => r.text())); })();
