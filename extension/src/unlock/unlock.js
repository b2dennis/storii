// Unlocking from the page: shown in an extension frame inside the content script's picker, so the page can't read the
// master password (keystrokes inside a cross-origin frame never reach it). Tells the picker when it's done.

function call(type, msg = {}) {
  return new Promise((resolve, reject) =>
    chrome.runtime.sendMessage({ type, ...msg }, (r) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      r?.error ? reject(new Error(r.error)) : resolve(r?.result);
    }));
}

const $ = (id) => document.getElementById(id);
const tell = (what) => parent.postMessage({ storii: what }, '*');
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function busy(on) {
  for (const b of document.querySelectorAll('button')) b.disabled = on;
}

$('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!$('pw').value) return $('pw').focus();
  busy(true);
  $('err').textContent = '';
  try {
    await call('unlock', { password: $('pw').value });
    $('pw').value = '';
    tell('unlocked');
  } catch (err) {
    $('err').textContent = err.message;
    $('pw').select();
  } finally {
    busy(false);
  }
});

// Passkey unlock needs the page to let this frame use WebAuthn; where it can't, the popup does it instead.
async function quick(q) {
  busy(true);
  $('err').textContent = '';
  try {
    const cred = await navigator.credentials.get({ publicKey: {
      ...(q.rpId ? { rpId: q.rpId } : {}),
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: unb64(q.credentialId) }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: unb64(q.salt) } } },
    } });
    const first = cred.getClientExtensionResults().prf?.results?.first;
    if (!first) throw new Error('The authenticator didn’t return a key.');
    await call('quickUnlock', { prf: b64(first) });
    tell('unlocked');
  } catch (err) {
    if (err.name === 'NotAllowedError' || err.name === 'AbortError') $('pw').focus();
    else if (err.name === 'SecurityError' || err.name === 'NotSupportedError') {
      tell('close');
      call('openUnlock').catch(() => {});
    } else $('err').textContent = err.message;
  } finally {
    busy(false);
  }
}

document.addEventListener('keydown', (e) => e.key === 'Escape' && tell('close'));

(async () => {
  const st = await call('status');
  if (st.unlocked) return tell('unlocked');
  if (!st.configured || st.expired) {
    tell('close');
    return call('openUnlock');
  }
  $('who').textContent = `${st.username} · ${st.server}`;
  const q = await call('quickUnlockInfo').catch(() => null);
  if (q && window.PublicKeyCredential) {
    $('quick').hidden = false;
    $('quick').onclick = () => quick(q);
  }
  $('pw').focus();
})();
