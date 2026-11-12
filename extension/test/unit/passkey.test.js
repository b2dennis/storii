// storii's passkeys checked by an independent relying party (SimpleWebAuthn).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { createPasskey, assertPasskey, rpIdAllowed, b64u } from '../../src/lib/passkey.js';

test('register and sign in', async () => {
  const origin = 'https://login.example.com', rpId = 'example.com';
  const challenge = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const { passkey, response } = await createPasskey({ rpId, origin, challenge, user: { id: b64u([1, 2, 3]), name: 'me@example.com', displayName: 'Me' } });
  const reg = await verifyRegistrationResponse({
    response: { id: response.id, rawId: response.id, type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: response.clientDataJSON, attestationObject: response.attestationObject, transports: response.transports } },
    expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpId, requireUserVerification: true,
  });
  assert.ok(reg.verified);
  assert.equal(reg.registrationInfo.credentialBackedUp, true);

  for (let i = 0; i < 3; i++) {
    const c2 = b64u(crypto.getRandomValues(new Uint8Array(32)));
    const a = await assertPasskey({ passkey, origin, challenge: c2 });
    const auth = await verifyAuthenticationResponse({
      response: { id: a.id, rawId: a.id, type: 'public-key', clientExtensionResults: {},
        response: { clientDataJSON: a.clientDataJSON, authenticatorData: a.authenticatorData, signature: a.signature, userHandle: a.userHandle } },
      expectedChallenge: c2, expectedOrigin: origin, expectedRPID: rpId, requireUserVerification: true,
      credential: { id: reg.registrationInfo.credential.id, publicKey: reg.registrationInfo.credential.publicKey, counter: 0 },
    });
    assert.ok(auth.verified);
  }
});

test('rp ids', () => {
  assert.ok(rpIdAllowed('example.com', 'https://login.example.com'));
  assert.ok(rpIdAllowed('login.example.com', 'https://login.example.com'));
  assert.ok(rpIdAllowed('localhost', 'http://localhost:8080'));
  assert.ok(!rpIdAllowed('example.com', 'http://example.com'));
  assert.ok(!rpIdAllowed('other.com', 'https://example.com'));
  assert.ok(!rpIdAllowed('com', 'https://example.com'));
  assert.ok(!rpIdAllowed('co.uk', 'https://shop.co.uk'));
  assert.ok(!rpIdAllowed('ample.com', 'https://example.com'));
});
