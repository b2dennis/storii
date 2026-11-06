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
