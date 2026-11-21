// Password health, as internal/vault/health.go (shared cases: testdata/health.json).
export const WEAK_BITS = 50;
export const PWNED_RANGE_URL = 'https://api.pwnedpasswords.com/range/';

// Too short or too guessable: under 8 characters, under 5 different ones, or under WEAK_BITS by
// length × log2(pool), where the pool counts 26 lowercase, 26 uppercase, 10 digits and 33 for anything else.
export function isWeak(pw) {
  const r = [...pw];
  if (r.length < 8) return true;
  if (new Set(r).size < 5) return true;
  let lower = false, upper = false, digit = false, other = false;
  for (const c of r) {
    if (c >= 'a' && c <= 'z') lower = true;
    else if (c >= 'A' && c <= 'Z') upper = true;
    else if (c >= '0' && c <= '9') digit = true;
    else other = true;
  }
  const pool = (lower ? 26 : 0) + (upper ? 26 : 0) + (digit ? 10 : 0) + (other ? 33 : 0);
  return r.length * Math.log2(pool) < WEAK_BITS;
}

const passwordItems = (items) => Object.entries(items)
  .filter(([, it]) => it.kind === 'secret' && it.type === 'password' && it.fields?.password);

// items: id → item. Weak ids, and groups of ids sharing a password (sorted, groups by their first id).
export function checkHealth(items) {
  const weak = [];
  const by = new Map();
  for (const [id, it] of passwordItems(items)) {
    const pw = it.fields.password;
    if (isWeak(pw)) weak.push(id);
    by.set(pw, [...(by.get(pw) || []), id]);
  }
  const cmp = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  const reused = [...by.values()].filter((g) => g.length > 1).map((g) => g.sort(cmp)).sort((a, b) => cmp(a[0], b[0]));
  return { weak: weak.sort(cmp), reused };
}

// The uppercase SHA-1 split into the 5 characters sent to Have I Been Pwned and the rest, looked up in its answer.
export async function pwnedHash(pw) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-1', new TextEncoder().encode(pw)));
  const h = [...d].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return [h.slice(0, 5), h.slice(5)];
}

// How often suffix appears in a range answer ("SUFFIX:COUNT" lines; padding lines have count 0).
export function pwnedCount(body, suffix) {
  for (const line of body.split('\n')) {
    const [s, n] = line.trim().split(':');
    if (n !== undefined && s.toUpperCase() === suffix.toUpperCase()) return parseInt(n, 10) || 0;
  }
  return 0;
}

// Asks Have I Been Pwned; only the first 5 hex digits of the SHA-1 leave the device, and the answer is padded.
export async function pwned(pw, fetchFn = fetch) {
  const [prefix, suffix] = await pwnedHash(pw);
  const res = await fetchFn(PWNED_RANGE_URL + prefix, { headers: { 'Add-Padding': 'true' } });
  if (!res.ok) throw new Error(`Breach check failed (${res.status})`);
  return pwnedCount(await res.text(), suffix);
}
