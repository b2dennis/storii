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

let up = false;
let site, siteURL, ctx, extId;

before(async () => {
  up = await fetch(`${SERVER}/api/v2/ping`).then((r) => r.ok, () => false);
  if (!up) return;
  site = createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    if (req.url === '/otp') return res.end(OTP_PAGE);
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

  // A context for the test site, then a password and a 2FA secret in it.
  await popup.click('#ctxs');
  await popup.click('#add');
  await popup.fill('#name', 'Example');
  await popup.fill('#urls', siteURL);
  await popup.click('#save');
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
  }
});
