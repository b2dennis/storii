// storii v2 crypto (docs/CRYPTO.md), pinned by testdata/vectors.json.
import { argon2id } from '../vendor/hash-wasm.js';

const te = new TextEncoder();
const td = new TextDecoder();

export function toB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function newKdf() {
  return { alg: 'argon2id', salt: toB64(randomBytes(16)), iterations: 3, memory_kib: 65536, parallelism: 2 };
}

async function hkdf(ikm, info) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: te.encode(info) }, key, 256);
  return new Uint8Array(bits);
}

// Argon2id over the NFC-normalized password, split with HKDF-SHA256 into the auth key (sent to the server)
// and the wrap key (never leaves the device).
export async function deriveKeys(password, kdf) {
  if (kdf.alg !== 'argon2id') throw new Error(`unsupported kdf ${kdf.alg}`);
  const master = await argon2id({
    password: te.encode(password.normalize('NFC')),
    salt: fromB64(kdf.salt),
    iterations: kdf.iterations,
    memorySize: kdf.memory_kib,
    parallelism: kdf.parallelism,
    hashLength: 32,
    outputType: 'binary',
  });
  return { auth: await hkdf(master, 'storii auth'), wrap: await hkdf(master, 'storii wrap') };
}

async function aesKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

// base64(0x01 || nonce(12) || ciphertext || tag(16))
export async function seal(keyBytes, plaintext, aad, nonce = randomBytes(12)) {
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: te.encode(aad) }, await aesKey(keyBytes), plaintext));
  const out = new Uint8Array(1 + 12 + ct.length);
  out[0] = 1;
  out.set(nonce, 1);
  out.set(ct, 13);
  return toB64(out);
}

export async function open(keyBytes, data, aad) {
  let raw;
  try {
    raw = fromB64(data);
  } catch {
    throw new Error('decryption failed');
  }
  if (raw.length < 29 || raw[0] !== 1) throw new Error('decryption failed');
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(1, 13), additionalData: te.encode(aad) }, await aesKey(keyBytes), raw.slice(13)));
  } catch {
    throw new Error('decryption failed');
  }
}

export const wrapVaultKey = (wrap, vaultKey, nonce) => seal(wrap, vaultKey, 'storii:vault-key', nonce);

export async function unwrapVaultKey(wrap, wrapped) {
  const key = await open(wrap, wrapped, 'storii:vault-key');
  if (key.length !== 32) throw new Error('decryption failed');
  return key;
}

export const encryptItem = (vaultKey, id, item, nonce) =>
  seal(vaultKey, te.encode(typeof item === 'string' ? item : JSON.stringify(item)), `storii:item:${id}`, nonce);

export async function decryptItem(vaultKey, id, data) {
  return JSON.parse(td.decode(await open(vaultKey, data, `storii:item:${id}`)));
}
