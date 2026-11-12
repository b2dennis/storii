// Passkeys (WebAuthn) as storii's own authenticator: an ES256 key pair per credential, attestation "none",
// backed up and synced (BE and BS flags set, sign count 0). Pure functions; the background stores the results.

export const b64u = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

// storii's AAGUID (the bytes end in "storii").
export const AAGUID = Uint8Array.from('d1a8c0b05f2e4c3b9a7e73746f726969'.match(/../g), (h) => parseInt(h, 16));
const FLAGS = 0x01 | 0x04 | 0x08 | 0x10; // user present, user verified, backup eligible, backed up
const ES256 = { name: 'ECDSA', namedCurve: 'P-256' };

const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', data));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) out.set(p, (i += p.length) - p.length);
  return out;
};

// The CBOR WebAuthn needs: unsigned and negative ints, byte and text strings, maps (in the order given).
export function cbor(value) {
  const out = [];
  const head = (major, n) => {
    if (n < 24) out.push((major << 5) | n);
    else if (n < 256) out.push((major << 5) | 24, n);
    else if (n < 65536) out.push((major << 5) | 25, n >> 8, n & 255);
    else out.push((major << 5) | 26, (n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255);
  };
  const enc = (v) => {
    if (typeof v === 'number') v >= 0 ? head(0, v) : head(1, -1 - v);
    else if (typeof v === 'string') {
      const b = new TextEncoder().encode(v);
      head(3, b.length);
      out.push(...b);
    } else if (v instanceof Uint8Array) {
      head(2, v.length);
      for (const b of v) out.push(b);
    } else if (v instanceof Map) {
      head(5, v.size);
      for (const [k, x] of v) {
        enc(k);
        enc(x);
      }
    } else throw new Error('cbor: unsupported value');
  };
  enc(value);
  return new Uint8Array(out);
}

// WebCrypto signs ECDSA as r||s; WebAuthn wants DER.
export function derSignature(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    b = b.slice(i);
    if (b[0] & 0x80) b = concat(Uint8Array.of(0), b);
    return concat(Uint8Array.of(0x02, b.length), b);
  };
  const r = int(raw.slice(0, 32)), s = int(raw.slice(32));
  return concat(Uint8Array.of(0x30, r.length + s.length), r, s);
}

const signCount = new Uint8Array(4);

// Whether a page at origin may use rpId: https (or http://localhost), and rpId is the origin's host or a parent
// domain of it that's still a registrable domain (not "com" or "co.uk").
export function rpIdAllowed(rpId, origin) {
  let u;
  try {
    u = new URL(origin);
  } catch {
    return false;
  }
  const host = u.hostname;
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (host === 'localhost' || host.endsWith('.localhost')))) return false;
  if (!rpId || (host !== rpId && !host.endsWith('.' + rpId))) return false;
  const labels = rpId.split('.');
  if (host === rpId) return true;
  return labels.length >= 2 && !(labels.length === 2 && labels[0].length <= 3 && labels[1].length === 2);
}

function clientData(type, challenge, origin, crossOrigin) {
  return new TextEncoder().encode(JSON.stringify({ type, challenge, origin, crossOrigin: !!crossOrigin }));
}

/** navigator.credentials.create: a new passkey. challenge and user.id are base64url. */
export async function createPasskey({ rpId, origin, challenge, user, crossOrigin = false }) {
  const keys = await crypto.subtle.generateKey(ES256, true, ['sign', 'verify']);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', keys.publicKey)); // 0x04 | x | y
  const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, raw.slice(1, 33)], [-3, raw.slice(33, 65)]]));
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const authData = concat(await sha256(new TextEncoder().encode(rpId)), Uint8Array.of(FLAGS | 0x40), signCount,
    AAGUID, Uint8Array.of(credId.length >> 8, credId.length & 255), credId, cose);
  const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
  const cd = clientData('webauthn.create', challenge, origin, crossOrigin);
  return {
    passkey: {
      credential_id: b64u(credId), rp_id: rpId, user_handle: user.id, user_name: user.name || '',
      user_display_name: user.displayName || '', private_key: b64u(await crypto.subtle.exportKey('pkcs8', keys.privateKey)),
    },
    response: {
      id: b64u(credId), clientDataJSON: b64u(cd), attestationObject: b64u(attestationObject), authenticatorData: b64u(authData),
      publicKey: b64u(await crypto.subtle.exportKey('spki', keys.publicKey)), publicKeyAlgorithm: -7, transports: ['hybrid', 'internal'],
    },
  };
}

/** navigator.credentials.get with a stored passkey. */
export async function assertPasskey({ passkey, origin, challenge, crossOrigin = false }) {
  const authData = concat(await sha256(new TextEncoder().encode(passkey.rp_id)), Uint8Array.of(FLAGS), signCount);
  const cd = clientData('webauthn.get', challenge, origin, crossOrigin);
  const key = await crypto.subtle.importKey('pkcs8', unb64u(passkey.private_key), ES256, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, concat(authData, await sha256(cd))));
  return {
    id: passkey.credential_id, clientDataJSON: b64u(cd), authenticatorData: b64u(authData), signature: b64u(derSignature(sig)),
    userHandle: passkey.user_handle || null,
  };
}
