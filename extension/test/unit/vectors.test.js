import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { deriveKeys, toB64, fromB64, wrapVaultKey, unwrapVaultKey, encryptItem, decryptItem } from '../../src/lib/crypto.js';
import { totpFromFields, totpCode, parseOtpauth, totpFields } from '../../src/lib/totp.js';
import { matchesHost } from '../../src/lib/match.js';

const v = JSON.parse(readFileSync(new URL('../../../testdata/vectors.json', import.meta.url)));

test('kdf', async () => {
  for (const k of v.kdf) {
    const keys = await deriveKeys(k.password, k.kdf);
    assert.equal(toB64(keys.auth), k.auth_key, k.password);
    assert.equal(toB64(keys.wrap), k.wrap_key, k.password);
  }
});

test('vault key', async () => {
  const vk = v.vault_key;
  assert.equal(await wrapVaultKey(fromB64(vk.wrap_key), fromB64(vk.vault_key), fromB64(vk.nonce)), vk.wrapped);
  assert.equal(toB64(await unwrapVaultKey(fromB64(vk.wrap_key), vk.wrapped)), vk.vault_key);
  await assert.rejects(unwrapVaultKey(new Uint8Array(32), vk.wrapped));
});

test('items', async () => {
  for (const it of v.items) {
    const key = fromB64(it.vault_key);
    assert.equal(await encryptItem(key, it.id, it.plaintext, fromB64(it.nonce)), it.data);
    assert.deepEqual(await decryptItem(key, it.id, it.data), JSON.parse(it.plaintext));
    await assert.rejects(decryptItem(key, '00000000-0000-0000-0000-000000000000', it.data));
  }
});

test('totp', async () => {
  for (const c of v.totp) {
    assert.equal(await totpCode(totpFromFields(c.fields), c.time * 1000), c.code, JSON.stringify(c));
  }
});

test('otpauth', () => {
  for (const c of v.otpauth) {
    if (c.error) {
      assert.throws(() => parseOtpauth(c.uri), c.uri);
      continue;
    }
    const sorted = (o) => Object.fromEntries(Object.entries(o).sort());
    assert.deepEqual(sorted(totpFields(parseOtpauth(c.uri))), sorted(c.fields), c.uri);
  }
});

test('match', () => {
  for (const c of v.match) assert.equal(matchesHost(c.context_url, c.host), c.match, JSON.stringify(c));
});

test('cards', async () => {
  const { cardBrand, cardValid, cardMasked, normalizeExpiry } = await import('../../src/lib/card.js');
  const c = JSON.parse(readFileSync(new URL('../../../testdata/cards.json', import.meta.url)));
  for (const n of c.numbers) {
    assert.equal(cardBrand(n.number), n.brand, n.number);
    assert.equal(cardValid(n.number), n.valid, n.number);
    assert.equal(cardMasked(n.number), n.masked, n.number);
  }
  for (const e of c.expiry) assert.equal(normalizeExpiry(e.input), e.normalized, e.input);
});

test('password history', async () => {
  const { withHistory } = await import('../../src/lib/history.js');
  const h = JSON.parse(readFileSync(new URL('../../../testdata/history.json', import.meta.url)));
  for (const c of h.cases) assert.deepEqual(withHistory(c.prev, c.next, h.now).history, c.want, c.name);
});

test('password health', async () => {
  const { isWeak, checkHealth, pwnedHash, pwnedCount, pwned } = await import('../../src/lib/health.js');
  const h = JSON.parse(readFileSync(new URL('../../../testdata/health.json', import.meta.url)));
  for (const c of h.weak) assert.equal(isWeak(c.password), c.weak, c.password);
  assert.deepEqual(checkHealth(h.items), h.health);
  const p = h.pwned;
  assert.deepEqual(await pwnedHash(p.password), [p.prefix, p.suffix]);
  assert.equal(pwnedCount(p.body, p.suffix), p.count);
  assert.equal(pwnedCount(p.body, p.missing_suffix), 0);
  assert.equal(pwnedCount(p.body, p.padding_suffix), 0);
  const seen = [];
  const n = await pwned(p.password, async (url, init) => {
    seen.push([url, init.headers['Add-Padding']]);
    return { ok: true, text: async () => p.body };
  });
  assert.equal(n, p.count);
  assert.deepEqual(seen, [[`https://api.pwnedpasswords.com/range/${p.prefix}`, 'true']]);
});

test('backup', async () => {
  const { openBackup, sealBackup, isBackup, restorePlan, WRONG_PASSWORD } = await import('../../src/lib/backup.js');
  const b = JSON.parse(readFileSync(new URL('../../../testdata/backup.json', import.meta.url)));
  const file = JSON.stringify(b.file);
  assert.ok(isBackup(file) && !isBackup('{"items":[]}') && !isBackup('id,name'));
  assert.deepEqual(await openBackup(b.password, file), b.items);
  await assert.rejects(openBackup('wrong', file), { message: WRONG_PASSWORD });
  // Same inputs as the Go -update run give the same file.
  const again = await sealBackup(b.password, b.items, { kdf: b.file.kdf, now: new Date(b.file.exported_at), nonce: new Uint8Array(12).fill(7) });
  assert.equal(JSON.parse(again).data, b.file.data);
  const ids = Object.keys(b.items);
  const plan = restorePlan({ ...b.items, 'not-a-uuid': { kind: 'secret', name: 'x' } }, new Set([ids[0]]));
  assert.deepEqual(plan.add.map(([id]) => id).sort(), ids.slice(1).sort());
  assert.equal(plan.skipped, 2);
});
