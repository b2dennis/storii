// Carries passkey requests from webauthn.js (the page's world) to the background and the answer back. The page can
// send these events too: the background trusts only the frame's real origin, which the browser reports.
(() => {
  if (window.__storiiBridge) return;
  window.__storiiBridge = true;
  window.addEventListener('storii-webauthn', (e) => {
    let req;
    try {
      req = JSON.parse(e.detail);
    } catch {
      return;
    }
    if (typeof req?.id !== 'string') return;
    const reply = (r) => window.dispatchEvent(new CustomEvent('storii-webauthn-reply', { detail: JSON.stringify({ ...r, id: req.id }) }));
    try {
      chrome.runtime.sendMessage({ type: 'passkey', op: req.op, data: req.data }, (r) => {
        if (chrome.runtime.lastError || !r || r.error) return reply({ fallback: true });
        reply(r.result);
      });
    } catch {
      reply({ fallback: true }); // the extension was updated or removed under this page
    }
  });
})();
