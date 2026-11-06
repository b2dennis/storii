// RFC 6238 codes and otpauth:// URIs, matching internal/vault/totp.go.
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(s) {
  s = (s || '').replace(/[\s=-]/g, '').toUpperCase();
  if (!s) throw new Error('TOTP secret is not valid base32');
  let bits = 0, value = 0;
  const out = [];
  for (const c of s) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error('TOTP secret is not valid base32');
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  // Same leniency as Go's decoder: only impossible lengths are rejected, leftover bits are ignored.
  if ([1, 3, 6].includes(s.length % 8)) throw new Error('TOTP secret is not valid base32');
  if (!out.length) throw new Error('TOTP secret is not valid base32');
  return new Uint8Array(out);
}

export function base32Encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// Parses a totp secret's fields with the defaults (SHA1, 6 digits, 30 s).
export function totpFromFields(f = {}) {
  const t = {
    secret: base32Decode(f.secret),
    algorithm: (f.algorithm || 'SHA1').toUpperCase(),
    digits: f.digits ? Number(f.digits) : 6,
    period: f.period ? Number(f.period) : 30,
    issuer: f.issuer || '',
    account: f.account || '',
  };
  if (!['SHA1', 'SHA256', 'SHA512'].includes(t.algorithm)) throw new Error(`unsupported TOTP algorithm ${t.algorithm}`);
  if (!Number.isInteger(t.digits) || t.digits < 6 || t.digits > 10) throw new Error('TOTP digits must be 6 to 10');
  if (!Number.isInteger(t.period) || t.period < 1 || t.period > 300) throw new Error('TOTP period must be 1 to 300 seconds');
  return t;
}

// The inverse of totpFromFields, leaving out defaults.
export function totpFields(t) {
  const f = { secret: base32Encode(t.secret) };
  if (t.algorithm && t.algorithm !== 'SHA1') f.algorithm = t.algorithm;
  if (t.digits && t.digits !== 6) f.digits = String(t.digits);
  if (t.period && t.period !== 30) f.period = String(t.period);
  if (t.issuer) f.issuer = t.issuer;
  if (t.account) f.account = t.account;
  return f;
}

export async function totpCode(t, nowMs = Date.now()) {
  const counter = Math.floor(nowMs / 1000 / t.period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const hash = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' }[t.algorithm];
  const key = await crypto.subtle.importKey('raw', t.secret, { name: 'HMAC', hash }, false, ['sign']);
  const sum = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = sum[sum.length - 1] & 0x0f;
  const v = new DataView(sum.buffer).getUint32(off) & 0x7fffffff;
  return String(BigInt(v) % 10n ** BigInt(t.digits)).padStart(t.digits, '0');
}

export function totpRemaining(t, nowMs = Date.now()) {
  return t.period - (Math.floor(nowMs / 1000) % t.period);
}

export function parseOtpauth(uri) {
  let u;
  try {
    u = new URL(uri.trim());
  } catch {
    throw new Error('not an otpauth:// URI');
  }
  if (u.protocol !== 'otpauth:') throw new Error('not an otpauth:// URI');
  if (u.host !== 'totp' && u.hostname !== 'totp') throw new Error('only TOTP (time-based) codes are supported');
  const q = u.searchParams;
  const f = { secret: q.get('secret') || '', algorithm: q.get('algorithm') || '', digits: q.get('digits') || '',
    period: q.get('period') || '', issuer: q.get('issuer') || '' };
  const label = decodeURIComponent(u.pathname.replace(/^\//, ''));
  const i = label.indexOf(':');
  if (i >= 0) {
    if (!f.issuer) f.issuer = label.slice(0, i).trim();
    f.account = label.slice(i + 1).trim();
  } else {
    f.account = label;
  }
  return totpFromFields(f);
}
