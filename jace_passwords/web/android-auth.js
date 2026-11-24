"use strict";
/* The Android app's sign-in return page, when Android opened it in the browser instead of the app (the app's
   verified link isn't set up, or the app isn't installed). Hands the sign-in to the Jace Passwords app only:
   an intent addressed to its package, so no other app can catch it. The token is never sent to any server. */
(() => {
  const frag = location.hash.slice(1);
  history.replaceState(null, "", location.pathname); // don't keep the token in the address bar or history
  const btn = document.getElementById("open");
  if (!/(^|&)token=/.test(frag)) {
    document.getElementById("h").textContent = "Sign-in didn't finish";
    document.getElementById("p").textContent = "Go back to the Jace Passwords app and try again.";
    btn.remove();
    return;
  }
  const intent = `intent://auth?${frag}#Intent;scheme=jacepasswords;package=com.okjace.jacepasswords;end`;
  btn.href = intent;
  location.href = intent;
})();
