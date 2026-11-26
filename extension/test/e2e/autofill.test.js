// End-to-end: the built Chrome extension against a storii dev server (go run ./cmd/storii-devserver).
//   STORII_E2E_SERVER=http://localhost:9999 npm run e2e
// Skipped when no server answers. With STORII_E2E_CLI pointing at a built `storii` binary it also checks that the
// Go CLI reads what the extension wrote.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
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
const CHECKOUT_PAGE = `<!doctype html><title>Checkout</title><form action="/welcome" method="post" style="margin:40px">
  <input id="num" autocomplete="cc-number" placeholder="Card number"><br>
  <input id="holder" name="cardholder" placeholder="Name on card"><br>
  <select id="mm" name="exp-month"><option value="">MM</option>${Array.from({ length: 12 }, (_, i) => `<option>${String(i + 1).padStart(2, '0')}</option>`).join('')}</select>
  <select id="yy" name="exp-year"><option value="">YYYY</option><option>2028</option><option>2029</option><option>2030</option></select>
  <input id="cvc" name="cvc" placeholder="CVC" maxlength="4"><br>
  <iframe src="http://localhost:PORT/evil" style="width:300px;height:60px"></iframe>
  <button type="submit">Pay now</button>
</form>`;

// Like Stripe Elements: number, expiry and CVC each in an iframe of a payment host, and a Pay button (type=button)
// that stays on the page.
const SPA_CHECKOUT = `<!doctype html><title>Pay</title><div style="margin:40px">
  <iframe id="fn" src="PAY/field?ac=cc-number" style="width:300px;height:40px"></iframe>
  <iframe id="fe" src="PAY/field?ac=cc-exp" style="width:300px;height:40px"></iframe>
  <iframe id="fc" src="PAY/field?ac=cc-csc" style="width:300px;height:40px"></iframe>
  <button type="button" onclick="this.textContent='Paid'">Pay CHF 20.00</button></div>`;

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
    if (req.url === '/spa-checkout') return res.end(SPA_CHECKOUT.replaceAll('PAY', `http://localhost:${site.address().port}`));
    if (req.url.startsWith('/field?')) return res.end(`<!doctype html><input id="i" autocomplete="${new URL(req.url, 'http://x').searchParams.get('ac')}" style="width:200px">`);
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
  // A sync works, also against an older server whose missing endpoints answer in plain text.
  const synced = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'sync' }, (x) => r(x))));
  assert.equal(synced.error, undefined);

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

  // A new card typed at checkout is offered for saving after paying.
  await page.goto(`${siteURL}/checkout`);
  await page.fill('#num', '5555 5555 5555 4444');
  await page.keyboard.press('Escape');
  await page.fill('#holder', 'New Card');
  await page.selectOption('#mm', '03');
  await page.selectOption('#yy', '2030');
  await page.fill('#cvc', '987');
  await Promise.all([page.waitForURL('**/welcome'), page.click('button[type=submit]')]);
  await page.waitForTimeout(800);
  await page.mouse.click(page.viewportSize().width - 12 - 40, 12 + 70);
  await page.waitForTimeout(800);
  const withCard = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  const newCard = withCard.find((i) => i.type === 'card' && i.fields?.number === '5555555555554444');
  assert.ok(newCard, 'the typed card was saved');
  assert.deepEqual([newCard.name, newCard.fields.expiry, newCard.fields.cvc, newCard.fields.cardholder], ['Mastercard 4444', '03/30', '987', 'New Card']);

  // A card in payment-provider iframes, paid with a button that doesn't leave the page: offered right away.
  await page.goto(`${siteURL}/spa-checkout`);
  const field = (ac) => page.frames().find((f) => f.url().includes(`ac=${ac}`));
  for (const [ac, v] of [['cc-number', '4000 0566 5566 5556'], ['cc-exp', '11 / 31'], ['cc-csc', '321']]) {
    await field(ac).fill('#i', v);
    await page.keyboard.press('Escape');
  }
  await page.click('button');
  await page.waitForTimeout(1200);
  await page.mouse.click(page.viewportSize().width - 12 - 40, 12 + 70);
  await page.waitForTimeout(800);
  const withSpaCard = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  const spaCard = withSpaCard.find((i) => i.type === 'card' && i.fields?.number === '4000056655665556');
  assert.ok(spaCard, 'the card typed into payment iframes was saved');
  assert.deepEqual([spaCard.name, spaCard.fields.expiry, spaCard.fields.cvc], ['Visa 5556', '11/31', '321']);

  // More writes than the server takes in one request (a big import): sent in chunks.
  const many = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'saveMany', changes:
    Array.from({ length: 2100 }, (_, i) => ({ item: { kind: 'secret', type: 'note', name: `Bulk ${i}`, fields: { note: 'x' } } })) }, r)));
  assert.ok(!many.error, many.error);
  const afterBulk = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  assert.equal(afterBulk.filter((i) => i.name?.startsWith('Bulk ')).length, 2100);
  const bulkIds = afterBulk.filter((i) => i.name?.startsWith('Bulk ')).map((i) => i.id);
  const gone = await popup.evaluate((ids) => new Promise((r) => chrome.runtime.sendMessage({ type: 'delete', ids }, r)), bulkIds);
  assert.ok(!gone.error, gone.error);

  // Changing a password keeps the old one in the item's history.
  // (Its own item: later steps rely on the other logins' passwords.)
  const [histId] = (await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'saveMany', changes: [
    { item: { kind: 'secret', type: 'password', name: 'History test', fields: { username: 'h', password: 'first-Pw-0' } } }] }, r)))).result;
  const login = (await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result)))))
    .find((i) => i.id === histId);
  const { id: loginId, ...loginItem } = login;
  await popup.evaluate(({ id, item }) => new Promise((r) => chrome.runtime.sendMessage({ type: 'saveMany', changes: [{ id, item }] }, r)),
    { id: loginId, item: { ...loginItem, fields: { ...loginItem.fields, password: 'changed-Pw-1' } } });
  const withHistory = (await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result)))))
    .find((i) => i.id === loginId);
  assert.equal(withHistory.fields.password, 'changed-Pw-1');
  assert.equal(withHistory.history?.[0]?.value, login.fields.password);

  // Password health: two items sharing a weak password, and a breach check against a stand-in for Have I Been Pwned.
  await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'saveMany', changes: [
    { item: { kind: 'secret', type: 'password', name: 'Weak One', fields: { password: 'hunter22' } } },
    { item: { kind: 'secret', type: 'password', name: 'Weak Two', fields: { password: 'hunter22' } } }] }, r)));
  await popup.reload();
  await popup.waitForSelector('#q');
  await popup.click('#settings');
  await popup.click('#health');
  await popup.waitForSelector('#breach');
  // Within a group, entries follow their (random) ids.
  assert.match(await popup.textContent('#app'), /Reused passwords.*Weak (One|Two).*Weak (One|Two).*Weak passwords.*Weak (One|Two).*Weak (One|Two)/s);
  const [hPre, hSuf] = await popup.evaluate(async () => (await import('../lib/health.js')).pwnedHash('hunter22'));
  const pwnedRequests = [];
  await popup.route('https://api.pwnedpasswords.com/range/*', (route) => {
    const url = route.request().url();
    pwnedRequests.push([url, route.request().headers()['add-padding']]);
    route.fulfill({ status: 200, body: url.endsWith('/' + hPre) ? `${hSuf}:7\r\nABC:0\r\n` : 'ABC:0\r\n' });
  });
  await popup.click('#breach');
  await popup.waitForFunction(() => document.querySelector('#app').textContent.includes('Seen 7 times'), null, { timeout: 15000 });
  assert.ok(pwnedRequests.length > 0 && pwnedRequests.every(([u, pad]) => /\/range\/[0-9A-F]{5}$/.test(u) && pad === 'true'),
    JSON.stringify(pwnedRequests));
  assert.equal((await popup.$$('text=Seen 7 times')).length, 2);
  await popup.unroute('https://api.pwnedpasswords.com/range/*');

  // Trash: a deleted secret shows up under Recently deleted and comes back with Restore.
  const weakOne = (await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, r))))
    .result.find((i) => i.name === 'Weak One');
  await popup.evaluate((id) => new Promise((r) => chrome.runtime.sendMessage({ type: 'delete', ids: [id] }, r)), weakOne.id);
  await popup.reload();
  await popup.waitForSelector('#q');
  await popup.click('#settings');
  await popup.click('#trash');
  await popup.waitForSelector(`[data-restore="${weakOne.id}"]`);
  assert.match(await popup.textContent('#app'), /Weak One.*deleted/s);
  await popup.click(`[data-restore="${weakOne.id}"]`);
  await popup.waitForSelector(`[data-restore="${weakOne.id}"]`, { state: 'detached', timeout: 15000 });
  const back = (await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, r)))).result;
  assert.ok(back.some((i) => i.id === weakOne.id && i.fields.password === 'hunter22'));

  // Backups: download one on the backups page, delete a secret, and restore it from the file.
  const bk = await ctx.newPage();
  await bk.goto(`chrome-extension://${extId}/backup/backup.html`);
  await bk.fill('#pw', 'short');
  await bk.fill('#pw2', 'short');
  await bk.click('#download');
  assert.match(await bk.textContent('#exportErr'), /12 characters/);
  await bk.fill('#pw', 'Backup-Horse-77x');
  await bk.fill('#pw2', 'Backup-Horse-77x');
  const [dl] = await Promise.all([bk.waitForEvent('download'), bk.click('#download')]);
  const backupText = readFileSync(await dl.path(), 'utf8');
  assert.ok(JSON.parse(backupText).storii_backup === 1 && !backupText.includes('hunter22'));
  const weakTwo = back.find((i) => i.name === 'Weak Two');
  await popup.evaluate((id) => new Promise((r) => chrome.runtime.sendMessage({ type: 'delete', ids: [id] }, r)), weakTwo.id);
  await bk.setInputFiles('#file', { name: 'b.json', mimeType: 'application/json', buffer: Buffer.from(backupText) });
  await bk.fill('#rpw', 'wrong');
  await bk.click('#check');
  await bk.waitForFunction(() => document.querySelector('#restoreErr').textContent.includes('Wrong backup password'), null, { timeout: 30000 });
  await bk.fill('#rpw', 'Backup-Horse-77x');
  await bk.click('#check');
  await bk.waitForSelector('#go:not([hidden])', { timeout: 30000 });
  assert.match(await bk.textContent('#summary'), /1 to restore.*Weak Two/s);
  await bk.click('#go');
  await bk.waitForFunction(() => document.querySelector('#restored').textContent.startsWith('Restored 1 item'), null, { timeout: 30000 });
  const afterRestore = (await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, r)))).result;
  assert.ok(afterRestore.some((i) => i.id === weakTwo.id && i.fields.password === 'hunter22'));
  await bk.close();

  // Locked: the card is still offered, and the bar unlocks storii first.
  await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'lock' }, r)));
  await page.goto(`${siteURL}/checkout`);
  await page.fill('#num', '3782 822463 10005');
  await page.keyboard.press('Escape');
  await page.fill('#cvc', '4321');
  await Promise.all([page.waitForURL('**/welcome'), page.click('button[type=submit]')]);
  await page.waitForTimeout(800);
  await page.mouse.click(page.viewportSize().width - 12 - 40, 12 + 70);
  const barUnlock = await (async () => {
    for (let i = 0; i < 30; i++) {
      const f = page.frames().find((x) => x.url().includes('unlock.html'));
      if (f) return f;
      await page.waitForTimeout(100);
    }
  })();
  assert.ok(barUnlock, "the save bar asks to unlock");
  await barUnlock.fill('#pw', MASTER);
  await barUnlock.press('#pw', 'Enter');
  await page.waitForTimeout(1500);
  const afterUnlock = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  assert.ok(afterUnlock?.some((i) => i.type === 'card' && i.fields?.number === '378282246310005'), 'the card typed while locked was saved');

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
  await pickFirst(page, 'input[name=email]'); // "Unlock storii": the picker turns into the unlock frame
  assert.equal(await page.inputValue('input[name=pass]'), '');
  // Unlocking right on the page, in storii's own frame, then picking the login.
  let unlockFrame;
  for (let i = 0; i < 50 && !unlockFrame; i++) {
    unlockFrame = page.frames().find((f) => f.url().includes('/unlock/unlock.html'));
    if (!unlockFrame) await page.waitForTimeout(100);
  }
  assert.ok(unlockFrame, 'unlock frame shown in the picker');
  // The page sees neither the field nor what's typed into it.
  const seen = await page.evaluate(() => { const k = []; addEventListener('keydown', (e) => k.push(e.key), true); window.__keys = k; return document.querySelectorAll('input[type=password]').length; });
  await unlockFrame.fill('#pw', 'wrong-password');
  await unlockFrame.press('#pw', 'Enter');
  await unlockFrame.waitForSelector('#err:not(:empty)');
  await unlockFrame.fill('#pw', MASTER);
  await unlockFrame.press('#pw', 'Enter');
  // The picker comes back with the matches once the unlock frame is gone.
  for (let i = 0; i < 100 && page.frames().some((f) => f.url().includes('/unlock/unlock.html')); i++) await page.waitForTimeout(100);
  await page.waitForTimeout(500);
  assert.deepEqual(await page.evaluate(() => window.__keys), []);
  assert.equal(seen, 1);
  const emailBox = await page.locator('input[name=email]').boundingBox();
  await page.mouse.click(emailBox.x + 60, emailBox.y + emailBox.height + 22);
  await page.waitForTimeout(300);
  // One of this site's logins (the picker's order varies; the reset step above saved a generated one too).
  const sitePasswords = (await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result)))))
    .filter((i) => i.type === 'password').map((i) => i.fields.password);
  assert.ok(sitePasswords.includes(await page.inputValue('input[name=pass]')), 'filled one of the saved logins');

  // Importing a Zen/Firefox password export from the import page; a second import of the same file adds nothing.
  const imp = await ctx.newPage();
  await imp.goto(`chrome-extension://${extId}/import/import.html`);
  const csv = { name: 'logins.csv', mimeType: 'text/csv', buffer: Buffer.from(
    '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\r\n' +
    '"https://imported.example.org","zen@example.org","from-zen","","https://imported.example.org","{a}","1","1","1"\r\n' +
    `"${siteURL}","me@example.com","hunter2-example","","","{b}","1","1","1"\r\n`) };
  await imp.setInputFiles('#file', csv);
  await imp.waitForSelector('#ready:not([hidden])');
  assert.match(await imp.textContent('#summary'), /2 logins in the file\s*1 new\s*1 already in storii/);
  await imp.click('#go');
  await imp.waitForSelector('#done:not([hidden])');
  assert.equal(await imp.textContent('#result'), 'Imported 1 login.');
  const all = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  const zen = all.find((i) => i.fields?.username === 'zen@example.org');
  assert.equal(zen?.fields.password, 'from-zen');
  assert.deepEqual(all.find((i) => i.id === zen.contexts[0])?.urls, ['https://imported.example.org']);
  await imp.reload();
  await imp.setInputFiles('#file', csv);
  await imp.waitForSelector('#ready:not([hidden])');
  assert.equal(await imp.isHidden('#go'), true);
  await imp.close();

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

test('sharing with a CLI user', { timeout: 120000 }, async (t) => {
  const cli = process.env.STORII_E2E_CLI;
  if (!up) return t.skip(`no dev server at ${SERVER}`);
  if (!cli) return t.skip('set STORII_E2E_CLI to a built storii binary');
  const bob = `${USER}b`;
  const env = { ...process.env, STORII_STATE: join(mkdtempSync(join(tmpdir(), 'storii-')), 'state.json'), STORII_PASSWORD: 'Bob-master-password-2' };
  const run = (...args) => execFileSync(cli, args, { env, input: '' }).toString();
  run('register', '--server', SERVER, '--user', bob);
  const bobFp = run('share').match(/fingerprint: ([0-9a-f ]+)/)[1].trim();

  const popup = await ctx.newPage();
  await popup.goto(`chrome-extension://${extId}/popup/popup.html`);
  const msg = (type, m = {}) => popup.evaluate(([type, m]) => new Promise((r) => chrome.runtime.sendMessage({ type, ...m }, (x) => r(x))), [type, m]);
  if (!(await msg('status')).result.unlocked) await msg('unlock', { password: MASTER });
  const [secretId] = (await msg('saveMany', { changes: [
    { item: { kind: 'secret', type: 'password', name: 'Family Netflix', fields: { username: 'fam', password: 'popcorn-1' } } }] })).result;

  const page = await ctx.newPage();
  await page.goto(`chrome-extension://${extId}/sharing/sharing.html`);
  await page.waitForFunction(() => /[0-9a-f]{4} /.test(document.querySelector('#fp').textContent));
  await page.fill('#newName', 'Family');
  await page.click('#create button');
  await page.waitForSelector('[data-add] input');
  await page.fill('[data-add] input', bob);
  await page.click('[data-add] button');
  // The fingerprint shown before adding is Bob's real one.
  await page.waitForSelector('[data-confirm]');
  assert.ok((await page.textContent('.confirm')).includes(bobFp), `${await page.textContent('.confirm')} vs ${bobFp}`);
  await page.click('[data-confirm]');
  await page.waitForFunction((b) => document.querySelector('[data-share]').textContent.includes(b) && !document.querySelector('[data-confirm]'), bob);
  await page.selectOption('[data-move] select', secretId);
  await page.click('[data-move] button');
  await page.waitForFunction(() => document.querySelector('[data-share] ul').textContent.includes('Family Netflix'));

  // Bob sees it in the CLI, changes the password; the extension gets the change.
  assert.match(run('ls'), /Family Netflix\s+\(fam\)\s+\{shared: Family\}/);
  assert.equal(run('get', 'Family Netflix', '--print').trim(), 'popcorn-1');
  run('edit', 'Family Netflix', '--field', 'password=popcorn-2');
  await msg('sync');
  const item = (await msg('items')).result.find((i) => i.id === secretId);
  assert.equal(item.fields.password, 'popcorn-2');
  assert.ok(item.share, 'still in the share');

  // Moving it home takes it out of the share for Bob; removing Bob drops the share for him.
  await page.reload();
  await page.click(`[data-home="${secretId}"]`);
  await page.waitForFunction(() => document.querySelector('[data-share] ul').textContent.includes('none yet'));
  assert.doesNotMatch(run('ls'), /Family Netflix/);
  page.on('dialog', (d) => d.accept());
  await page.click(`[data-remove="${bob}"]`);
  await page.waitForFunction((b) => !document.querySelector('[data-share]').textContent.includes(b), bob);
  assert.match(run('share'), /No shares yet/);
  await page.close();
  await popup.close();
});
