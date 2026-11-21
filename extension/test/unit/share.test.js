import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fromB64, toB64 } from '../../src/lib/crypto.js';
import * as share from '../../src/lib/share.js';

const v = JSON.parse(readFileSync(new URL('../../../testdata/sharing.json', import.meta.url)));
const b = fromB64;

test('sharing vectors', async () => {
  assert.equal(toB64(await share.publicKeyOf(b(v.private_key))), v.public_key);
  assert.equal(await share.fingerprint(b(v.public_key)), v.fingerprint);
  assert.equal(await share.sealSharePrivateKey(b(v.vault_key), b(v.private_key), new Uint8Array(12).fill(1)), v.sealed_private_key);
  assert.equal(toB64(await share.openSharePrivateKey(b(v.vault_key), v.sealed_private_key)), v.private_key);
  assert.equal(await share.wrapShareKey(b(v.public_key), v.share_id, b(v.share_key), b(v.ephemeral_private_key),
    new Uint8Array(12).fill(2)), v.wrapped_key);
  assert.equal(toB64(await share.unwrapShareKey(b(v.private_key), v.share_id, v.wrapped_key)), v.share_key);
  await assert.rejects(share.unwrapShareKey(b(v.private_key), '00000000-0000-0000-0000-000000000000', v.wrapped_key));
  assert.equal(await share.sealShareMeta(b(v.share_key), v.share_id, v.meta, new Uint8Array(12).fill(3)), v.meta_data);
  assert.deepEqual(await share.openShareMeta(b(v.share_key), v.share_id, v.meta_data), v.meta);
  assert.equal(await share.encryptShareItem(b(v.share_key), v.share_id, v.item_id, v.item, new Uint8Array(12).fill(4)), v.item_data);
  assert.deepEqual(await share.decryptShareItem(b(v.share_key), v.share_id, v.item_id, v.item_data), v.item);
  // Moving an item to another id or share breaks it.
  await assert.rejects(share.decryptShareItem(b(v.share_key), v.share_id, v.share_id, v.item_data));
});

test('fresh keys round-trip', async () => {
  const a = await share.newShareKeyPair();
  assert.equal(toB64(await share.publicKeyOf(a.priv)), toB64(a.pub));
  const sk = share.newShareKey();
  const w = await share.wrapShareKey(a.pub, 'x', sk);
  assert.equal(toB64(await share.unwrapShareKey(a.priv, 'x', w)), toB64(sk));
});
