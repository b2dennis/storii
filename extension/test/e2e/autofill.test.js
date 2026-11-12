// End-to-end: the built Chrome extension against a storii dev server (go run ./cmd/storii-devserver).
//   STORII_E2E_SERVER=http://localhost:9999 npm run e2e
// Skipped when no server answers. With STORII_E2E_CLI pointing at a built `storii` binary it also checks that the
// Go CLI reads what the extension wrote.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';
import { verifyRegistrationResponse, verifyAuthenticationResponse } from '@simplewebauthn/server';

const SERVER = process.env.STORII_E2E_SERVER || 'http://localhost:9999';
const EXT = fileURLToPath(new URL('../../dist/chrome/', import.meta.url));
const USER = `e2e${Date.now().toString(36)}`;
const MASTER = 'E2E-master-password-1';

const LOGIN_PAGE = `<!doctype html><title>Example login</title>
<form id="f" action="/welcome" method="post" style="margin:40px">
  <input name="email" type="email" autocomplete="username" placeholder="Email"><br>
  <input name="pass" type="password" autocomplete="current-password" placeholder="Password"><br>
  <button type="submit">Sign in</button>
</form>`;
const OTP_PAGE = `<!doctype html><title>2FA</title><form style="margin:40px">
  <label for="c">Authentication code</label><input id="c" name="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="6">
</form>`;

// Like Purelymail's reset page: a code from a text message, then the new password twice, no autocomplete hints.
const RESET_PAGE = `<!doctype html><title>Reset</title><form action="/welcome" method="post" style="margin:40px">
  <p>Enter the reset code:</p><input name="code"><br>
  <label>PASSWORD:<input name="pw" type="password"></label><br>
  <label>REPEAT PASSWORD:<input name="pw2" type="password"></label><br>
  <button type="submit">Submit</button>
</form>`;

// A checkout: card fields with autocomplete hints, expiry as two selects, and a third-party iframe (another host)
// with a card number field that must stay empty.
const CHECKOUT_PAGE = `<!doctype html><title>Checkout</title><form style="margin:40px">
  <input id="num" autocomplete="cc-number" placeholder="Card number"><br>
  <input id="holder" name="cardholder" placeholder="Name on card"><br>
  <select id="mm" name="exp-month"><option value="">MM</option>${Array.from({ length: 12 }, (_, i) => `<option>${String(i + 1).padStart(2, '0')}</option>`).join('')}</select>
  <select id="yy" name="exp-year"><option value="">YYYY</option><option>2028</option><option>2029</option><option>2030</option></select>
  <input id="cvc" name="cvc" placeholder="CVC" maxlength="4"><br>
  <iframe src="http://localhost:PORT/evil" style="width:300px;height:60px"></iframe>
</form>`;

let up = false;
let site, siteURL, ctx, extId;

before(async () => {
  up = await fetch(`${SERVER}/api/v2/ping`).then((r) => r.ok, () => false);
  if (!up) return;
  site = createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    if (req.url === '/otp') return res.end(OTP_PAGE);
    // Logs in, then redirects straight away to another host (as SSO and app subdomains do).
    if (req.url === '/hop') return res.end(`<!doctype html><script>location.replace('http://localhost:${site.address().port}/home')</script>`);
    if (req.url === '/home') return res.end('<!doctype html><title>Home</title><p>Signed in</p>');
    if (req.url === '/reset') return res.end(RESET_PAGE);
    if (req.url === '/rp') return res.end('<!doctype html><title>Passkey site</title><p>A site with passkeys</p>');
    if (req.url === '/checkout') return res.end(CHECKOUT_PAGE.replace('PORT', site.address().port));
    if (req.url === '/evil') return res.end('<!doctype html><input id="n" autocomplete="cc-number" style="width:200px">');
    if (req.url === '/welcome') return res.end('<!doctype html><title>Welcome</title><p>Welcome!</p>');
    res.end(LOGIN_PAGE);
  });
  await new Promise((r) => site.listen(0, '127.0.0.1', r));
  siteURL = `http://127.0.0.1:${site.address().port}`;
  ctx = await chromium.launchPersistentContext('', {
    channel: 'chromium',
    args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`],
  });
  let [sw] = ctx.serviceWorkers();
  sw ||= await ctx.waitForEvent('serviceworker');
  extId = new URL(sw.url()).host;
});

after(async () => {
  await ctx?.close();
  site?.close();
});

// The picker lives in a closed shadow root, so click where it is drawn: just below the field.
async function pickFirst(page, selector) {
  await page.click(selector);
  const box = await page.locator(selector).boundingBox();
  await page.waitForTimeout(400);
  await page.mouse.click(box.x + 60, box.y + box.height + 22);
}

test('register, add secrets in the popup, autofill, save prompt', { timeout: 120000 }, async (t) => {
  if (!up) return t.skip(`no dev server at ${SERVER}`);
  const popup = await ctx.newPage();
  await popup.goto(`chrome-extension://${extId}/popup/popup.html`);

  // Register.
  await popup.click('#switch');
  await popup.fill('#server', SERVER);
  await popup.fill('#user', USER);
  await popup.fill('#pw', MASTER);
  await popup.fill('#pw2', MASTER);
  await popup.click('#go');
  await popup.waitForSelector('#q', { timeout: 30000 });

  // Passkey unlock: Chromium's virtual authenticator stands in for Windows Hello / Touch ID (with PRF).
  const cdp = await popup.context().newCDPSession(popup);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal',
    hasResidentKey: true, hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true } });
  await popup.click('#settings');
  await popup.click('#quick');
  await popup.waitForFunction(() => !document.querySelector('#quick').disabled && (document.querySelector('#quick').checked || document.querySelector('#qerr').textContent), null, { timeout: 15000 });
  assert.equal(await popup.textContent('#qerr'), '');
  const msg = (type) => popup.evaluate((type) => new Promise((r) => chrome.runtime.sendMessage({ type }, (x) => r(x))), type);
  await msg('lock');
  await popup.reload();
  // The locked screen asks the authenticator straight away and opens the vault without the master password.
  await popup.waitForSelector('#q', { timeout: 15000 });
  assert.equal((await msg('status')).result.unlocked, true);

  // A context for the test site, then a password and a 2FA secret in it.
  await popup.click('#ctxs');
  await popup.click('#add');
  await popup.fill('#name', 'Example');
  await popup.fill('#urls', siteURL);
  await popup.click('#save');
  await popup.waitForTimeout(400); // saving re-renders the list; don't click the old #back
  await popup.click('#back');

  await popup.click('#add');
  await popup.fill('#name', 'Example login');
  await popup.fill('[data-f=username]', 'me@example.com');
  await popup.fill('[data-f=password]', 'hunter2-example');
  await popup.selectOption('#ctxpick', { label: 'Example' });
  await popup.click('#save');
  await popup.waitForSelector('#edit');
  await popup.click('#back');

  await popup.click('#add');
  await popup.selectOption('#type', 'totp');
  await popup.fill('#name', 'Example 2FA');
  await popup.fill('#totpin', 'otpauth://totp/Example:me?secret=JBSWY3DPEHPK3PXP&issuer=Example');
  await popup.selectOption('#ctxpick', { label: 'Example' });
  await popup.click('#save');
  await popup.waitForSelector('#edit');
  const code = (await popup.textContent('[data-code]')).replace(/\s/g, '');
  assert.match(code, /^\d{6}$/);

  // Autofill on the site: focus the username field, pick the login.
  const page = await ctx.newPage();
  await page.goto(siteURL);
  await pickFirst(page, 'input[name=email]');
  await page.waitForFunction(() => document.querySelector('input[name=pass]').value !== '');
  assert.equal(await page.inputValue('input[name=email]'), 'me@example.com');
  assert.equal(await page.inputValue('input[name=pass]'), 'hunter2-example');

  // One-time code field.
  await page.goto(`${siteURL}/otp`);
  await pickFirst(page, '#c');
  await page.waitForFunction(() => document.querySelector('#c').value.length === 6);
  const filled = await page.inputValue('#c');
  assert.ok(filled === code || /^\d{6}$/.test(filled)); // the code may have rolled over meanwhile

  // A login that isn't stored yet is offered for saving after submitting.
  await page.goto(siteURL);
  await page.fill('input[name=email]', 'other@example.com');
  await page.fill('input[name=pass]', 'brand-new-pass');
  await Promise.all([page.waitForURL('**/welcome'), page.click('button[type=submit]')]);
  await page.waitForTimeout(800);
  // The save bar is top right in a closed shadow root; its Save button is the last button.
  await page.mouse.click(page.viewportSize().width - 12 - 40, 12 + 70);
  await page.waitForTimeout(800);
  const items = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  const saved = items.find((i) => i.kind === 'secret' && i.fields?.username === 'other@example.com');
  assert.ok(saved, 'the submitted login was saved');
  assert.equal(saved.fields.password, 'brand-new-pass');

  // A login followed by an immediate redirect to another host is still offered, on the page it lands on.
  await page.goto(siteURL);
  await page.evaluate(() => { document.getElementById('f').action = '/hop'; });
  await page.fill('input[name=email]', 'redirect@example.com');
  await page.fill('input[name=pass]', 'redirected-pass');
  await Promise.all([page.waitForURL('**/home'), page.click('button[type=submit]')]);
  await page.waitForTimeout(800);
  await page.mouse.click(page.viewportSize().width - 12 - 40, 12 + 70);
  await page.waitForTimeout(800);
  const after = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  const hopped = after.find((i) => i.kind === 'secret' && i.fields?.username === 'redirect@example.com');
  assert.ok(hopped, 'the login submitted before the redirect was saved');
  assert.equal(hopped.fields.password, 'redirected-pass');

  // A new-password form gets a generated password in the picker; it fills both fields and is offered for saving.
  await page.goto(`${siteURL}/reset`);
  await page.fill('input[name=code]', '123456');
  await pickFirst(page, 'input[name=pw]');
  await page.waitForFunction(() => document.querySelector('input[name=pw]').value !== '');
  const generated = await page.inputValue('input[name=pw]');
  assert.equal(generated.length, 20);
  assert.match(generated, /[a-z]/); assert.match(generated, /[A-Z]/); assert.match(generated, /\d/);
  assert.equal(await page.inputValue('input[name=pw2]'), generated);
  assert.equal(await page.inputValue('input[name=code]'), '123456');
  await Promise.all([page.waitForURL('**/welcome'), page.click('button[type=submit]')]);
  await page.waitForTimeout(800);
  await page.mouse.click(page.viewportSize().width - 12 - 40, 12 + 70);
  await page.waitForTimeout(800);
  const withNew = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  const fresh = withNew.find((i) => i.kind === 'secret' && i.fields?.password === generated);
  assert.ok(fresh, 'the generated password was saved');
  assert.notEqual(fresh.fields.username, '123456', 'the reset code is not taken for the username');

  // Cards: saved in the popup, offered on a checkout's number field, filled into the page but not a foreign iframe.
  const saveCard = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'save', item: {
    kind: 'secret', type: 'card', name: 'Work Visa', fields: { cardholder: 'Dennis Test', number: '4242424242424242', expiry: '07/29', cvc: '123' },
  } }, (x) => r(x))));
  assert.ok(!saveCard.error, saveCard.error);
  await page.goto(`${siteURL}/checkout`);
  await page.waitForTimeout(500);
  await pickFirst(page, '#num');
  await page.waitForFunction(() => document.querySelector('#num').value !== '');
  assert.equal(await page.inputValue('#num'), '4242424242424242');
  assert.equal(await page.inputValue('#holder'), 'Dennis Test');
  assert.equal(await page.inputValue('#mm'), '07');
  assert.equal(await page.inputValue('#yy'), '2029');
  assert.equal(await page.inputValue('#cvc'), '123');
  const evil = page.frames().find((f) => f.url().includes('/evil'));
  assert.equal(await evil.inputValue('#n'), '', 'a third-party iframe gets no card');

  // Passkeys: storii answers navigator.credentials after the user approves in its window; an independent relying
  // party (SimpleWebAuthn) verifies the registration and the sign-in.
  const rpOrigin = `http://localhost:${site.address().port}`;
  const rp = await ctx.newPage();
  await rp.goto(`${rpOrigin}/rp`);
  const b64u = (b) => Buffer.from(b).toString('base64url');
  const regChallenge = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const approve = async (selector) => {
    const w = await ctx.waitForEvent('page', { predicate: (p) => p.url().includes('passkey='), timeout: 15000 });
    await w.waitForSelector(selector);
    await w.click(selector);
  };
  const [created] = await Promise.all([
    rp.evaluate(async (challenge) => {
      const bytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      const c = await navigator.credentials.create({ publicKey: { rp: { id: 'localhost', name: 'Passkey site' },
        user: { id: new Uint8Array([7, 7, 7]), name: 'me@localhost', displayName: 'Me' }, challenge: bytes(challenge + '='.repeat((4 - challenge.length % 4) % 4)),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { residentKey: 'required', userVerification: 'required' } } });
      return { json: c.toJSON(), isPkc: c instanceof PublicKeyCredential, alg: c.response.getPublicKeyAlgorithm() };
    }, regChallenge),
    approve('#save'),
  ]);
  assert.ok(created.isPkc, 'the page gets a PublicKeyCredential');
  assert.equal(created.alg, -7);
  const reg = await verifyRegistrationResponse({ response: created.json, expectedChallenge: regChallenge, expectedOrigin: rpOrigin,
    expectedRPID: 'localhost', requireUserVerification: true });
  assert.ok(reg.verified, 'registration verifies');

  const authChallenge = b64u(crypto.getRandomValues(new Uint8Array(32)));
  const [got] = await Promise.all([
    rp.evaluate(async (challenge) => {
      const bytes = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
      const c = await navigator.credentials.get({ publicKey: { rpId: 'localhost', challenge: bytes(challenge + '='.repeat((4 - challenge.length % 4) % 4)), userVerification: 'required' } });
      return c.toJSON();
    }, authChallenge),
    approve('[data-pk]'),
  ]);
  const auth = await verifyAuthenticationResponse({ response: got, expectedChallenge: authChallenge, expectedOrigin: rpOrigin,
    expectedRPID: 'localhost', requireUserVerification: true,
    credential: { id: reg.registrationInfo.credential.id, publicKey: reg.registrationInfo.credential.publicKey, counter: 0 } });
  assert.ok(auth.verified, 'sign-in verifies');
  assert.equal(Buffer.from(got.response.userHandle, 'base64url').toString('hex'), '070707');
  await rp.close();

  // Secrets of another site are refused to content scripts.
  const other = await ctx.newPage();
  await other.goto(`http://localhost:${site.address().port}/`); // a different host: localhost
  await other.click('input[name=email]');
  await other.waitForTimeout(500);
  assert.equal(await other.inputValue('input[name=pass]'), '');

  // Locking hides everything from pages.
  await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'lock' }, r)));
  await page.goto(siteURL);
  await pickFirst(page, 'input[name=email]'); // shows "Unlock storii" instead
  assert.equal(await page.inputValue('input[name=pass]'), '');

  // The Go CLI reads what the extension wrote.
  const cli = process.env.STORII_E2E_CLI;
  if (cli) {
    const env = { ...process.env, STORII_STATE: join(mkdtempSync(join(tmpdir(), 'storii-')), 'state.json'), STORII_PASSWORD: MASTER };
    execFileSync(cli, ['login', '--server', SERVER, '--user', USER], { env });
    const ls = execFileSync(cli, ['ls'], { env }).toString();
    assert.match(ls, /Example login .*me@example\.com.*\[Example\]/);
    assert.match(ls, /2fa\s+Example 2FA/);
    assert.equal(execFileSync(cli, ['get', 'Example login', '--print'], { env }).toString().trim(), 'hunter2-example');
    // Cards and passkeys written by the extension.
    assert.match(ls, /card\s+Work Visa\s+•••• 4242/);
    assert.match(ls, /passkey\s+Passkey site/);
    assert.equal(execFileSync(cli, ['get', 'Work Visa', '--print'], { env }).toString().trim(), '4242424242424242');
  }
});
