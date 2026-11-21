// Sharing crypto (docs/CRYPTO.md#sharing), pinned by testdata/sharing.json. X25519 through WebCrypto.
import { seal, open, toB64, fromB64 } from './crypto.js';

const te = new TextEncoder();
const td = new TextDecoder();
// PKCS#8 header for a raw X25519 private key (RFC 8410).
const PKCS8_PREFIX = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);

const cat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let i = 0;
  for (const p of parts) out.set(p, (i += p.length) - p.length);
  return out;
};

async function privateKey(raw) {
  if (raw.length !== 32) throw new Error('decryption failed');
  return crypto.subtle.importKey('pkcs8', cat(PKCS8_PREFIX, raw), { name: 'X25519' }, true, ['deriveBits']);
}

async function publicKey(raw) {
  if (raw.length !== 32) throw new Error('decryption failed');
  return crypto.subtle.importKey('raw', raw, { name: 'X25519' }, true, []);
}

export async function publicKeyOf(priv) {
  const jwk = await crypto.subtle.exportKey('jwk', await privateKey(priv));
  return fromB64(jwk.x.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (jwk.x.length % 4)) % 4));
}

export async function newShareKeyPair() {
  const kp = await crypto.subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', kp.privateKey));
  return { priv: pkcs8.slice(-32), pub: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)) };
}

export const sealSharePrivateKey = (vaultKey, priv, nonce) => seal(vaultKey, priv, 'storii:share-private-key', nonce);

export async function openSharePrivateKey(vaultKey, sealed) {
  const k = await open(vaultKey, sealed, 'storii:share-private-key');
  if (k.length !== 32) throw new Error('decryption failed');
  return k;
}

export async function fingerprint(pub) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', pub)).slice(0, 16);
  const hex = [...h].map((b) => b.toString(16).padStart(2, '0')).join('');
  return hex.match(/.{4}/g).join(' ');
}

export const newShareKey = () => crypto.getRandomValues(new Uint8Array(32));

async function wrapKey(privKey, theirPub, ephPub, recipientPub) {
  let shared;
  try {
    shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: await publicKey(theirPub) }, privKey, 256));
  } catch {
    throw new Error('decryption failed');
  }
  if (shared.every((b) => b === 0)) throw new Error('decryption failed'); // low-order point
  const ikm = await crypto.subtle.importKey('raw', cat(shared, ephPub, recipientPub), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode('storii share key') }, ikm, 256));
}

// "base64(ephemeral public key).envelope"; eph (raw private key) and nonce are for tests.
export async function wrapShareKey(recipientPub, shareId, shareKey, eph, nonce) {
  const e = eph ? { priv: eph, pub: await publicKeyOf(eph) } : await newShareKeyPair();
  const key = await wrapKey(await privateKey(e.priv), recipientPub, e.pub, recipientPub);
  return `${toB64(e.pub)}.${await seal(key, shareKey, `storii:share-key:${shareId}`, nonce)}`;
}

export async function unwrapShareKey(priv, shareId, wrapped) {
  const [ephB64, env] = wrapped.split('.');
  if (!env) throw new Error('decryption failed');
  const ephPub = fromB64(ephB64);
  const key = await wrapKey(await privateKey(priv), ephPub, ephPub, await publicKeyOf(priv));
  const sk = await open(key, env, `storii:share-key:${shareId}`);
  if (sk.length !== 32) throw new Error('decryption failed');
  return sk;
}

export const sealShareMeta = (shareKey, shareId, meta, nonce) =>
  seal(shareKey, te.encode(JSON.stringify({ name: meta.name })), `storii:share:${shareId}`, nonce);

export async function openShareMeta(shareKey, shareId, data) {
  return JSON.parse(td.decode(await open(shareKey, data, `storii:share:${shareId}`)));
}

export const encryptShareItem = (shareKey, shareId, id, item, nonce) =>
  seal(shareKey, te.encode(typeof item === 'string' ? item : JSON.stringify(item)), `storii:share:${shareId}:item:${id}`, nonce);

export async function decryptShareItem(shareKey, shareId, id, data) {
  return JSON.parse(td.decode(await open(shareKey, data, `storii:share:${shareId}:item:${id}`)));
}
