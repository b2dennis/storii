// storii's passkey hook, in the page's own JavaScript world (content_scripts world MAIN). It wraps
// navigator.credentials.create/get for WebAuthn requests and asks storii (through the isolated content script)
// first; when storii isn't used, the browser's own passkey dialog runs as usual. Everything secret stays in the
// extension: this script only ever sees what a page gets from a normal WebAuthn call.
(() => {
  const creds = navigator.credentials;
  if (!creds || !window.PublicKeyCredential || window.__storiiWebAuthn) return;
  Object.defineProperty(window, '__storiiWebAuthn', { value: true });
  const native = { create: creds.create.bind(creds), get: creds.get.bind(creds) };

  const b64u = (buf) => {
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const bytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer;

  let seq = 0;
  // Strings cross between the page's world and the extension's; objects don't (reliably).
  const ask = (op, data) => new Promise((resolve) => {
    const id = `${Date.now()}.${++seq}.${Math.random()}`;
    const onReply = (e) => {
      let r;
      try {
        r = JSON.parse(e.detail);
      } catch {
        return;
      }
      if (r.id !== id) return;
      window.removeEventListener('storii-webauthn-reply', onReply);
      resolve(r);
    };
    window.addEventListener('storii-webauthn-reply', onReply);
    window.dispatchEvent(new CustomEvent('storii-webauthn', { detail: JSON.stringify({ id, op, data }) }));
  });

  function credential(r, op, extensions) {
    const response = op === 'create' ? {
      clientDataJSON: bytes(r.clientDataJSON), attestationObject: bytes(r.attestationObject),
      getTransports: () => r.transports.slice(), getAuthenticatorData: () => bytes(r.authenticatorData),
      getPublicKey: () => bytes(r.publicKey), getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
    } : {
      clientDataJSON: bytes(r.clientDataJSON), authenticatorData: bytes(r.authenticatorData), signature: bytes(r.signature),
      userHandle: r.userHandle ? bytes(r.userHandle) : null,
    };
    const proto = op === 'create' ? window.AuthenticatorAttestationResponse : window.AuthenticatorAssertionResponse;
    if (proto) Object.setPrototypeOf(response, proto.prototype);
    const ext = extensions?.credProps ? { credProps: { rk: true } } : {};
    const json = { ...r };
    delete json.id;
    delete json.publicKeyAlgorithm;
    const cred = {
      id: r.id, rawId: bytes(r.id), type: 'public-key', authenticatorAttachment: 'platform', response,
      getClientExtensionResults: () => ({ ...ext }),
      toJSON: () => ({ id: r.id, rawId: r.id, type: 'public-key', authenticatorAttachment: 'platform', clientExtensionResults: ext,
        response: op === 'create' ? { ...json, publicKeyAlgorithm: r.publicKeyAlgorithm } : json }),
    };
    Object.setPrototypeOf(cred, PublicKeyCredential.prototype);
    return cred;
  }

  const fail = (r) => { throw new DOMException(r.message || 'The operation was not allowed.', r.error); };

  creds.create = function create(options) {
    const pk = options?.publicKey;
    if (!pk || !(pk.pubKeyCredParams || []).some((p) => p.alg === -7) || options.signal?.aborted) return native.create(options);
    return ask('create', {
      origin: location.origin, crossOrigin: window.top !== window, rpId: pk.rp?.id || location.hostname, rpName: pk.rp?.name || '',
      challenge: b64u(pk.challenge), user: { id: b64u(pk.user.id), name: pk.user.name || '', displayName: pk.user.displayName || '' },
      exclude: (pk.excludeCredentials || []).map((c) => b64u(c.id)),
    }).then((r) => (r.fallback ? native.create(options) : r.error ? fail(r) : credential(r.credential, 'create', pk.extensions)));
  };

  creds.get = function get(options) {
    const pk = options?.publicKey;
    // Conditional (autofill-style) requests stay with the browser; storii offers its passkeys on a button click.
    if (!pk || options.mediation === 'conditional' || options.signal?.aborted) return native.get(options);
    return ask('get', {
      origin: location.origin, crossOrigin: window.top !== window, rpId: pk.rpId || location.hostname,
      challenge: b64u(pk.challenge), allow: (pk.allowCredentials || []).map((c) => b64u(c.id)),
    }).then((r) => (r.fallback ? native.get(options) : r.error ? fail(r) : credential(r.credential, 'get', pk.extensions)));
  };
})();
