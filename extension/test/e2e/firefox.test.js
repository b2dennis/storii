// End-to-end: the built Firefox extension in a real Firefox (or Zen, via STORII_E2E_FIREFOX) against a storii dev
// server, driven over WebDriver BiDi. Skipped when no server answers or no Firefox is found.
//   STORII_E2E_SERVER=http://localhost:9999 npm run e2e
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import puppeteer from 'puppeteer-core';

const SERVER = process.env.STORII_E2E_SERVER || 'http://localhost:9999';
const FIREFOX = process.env.STORII_E2E_FIREFOX || '/usr/bin/firefox';
const EXT = fileURLToPath(new URL('../../dist/firefox/', import.meta.url));
const UUID = '0f1e2d3c-4b5a-4968-8776-655443322110'; // fixed moz-extension:// host for the popup
const USER = `ff${Date.now().toString(36)}`;
const MASTER = 'E2E-master-password-1';
const LOGIN_PAGE = `<!doctype html><title>Example login</title>
<form id="f" action="/welcome" method="post" style="margin:40px">
  <input name="email" type="email" autocomplete="username" placeholder="Email"><br>
  <input name="pass" type="password" autocomplete="current-password" placeholder="Password"><br>
  <button type="submit">Sign in</button>
</form>`;

let skip = '';
let site, siteURL, browser;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

before(async () => {
  if (!(await fetch(`${SERVER}/api/v2/ping`).then((r) => r.ok, () => false))) skip = `no dev server at ${SERVER}`;
  else if (!existsSync(FIREFOX)) skip = `no Firefox at ${FIREFOX}`;
  if (skip) return;
  site = createServer((req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.end(req.url === '/welcome' ? '<!doctype html><title>Welcome</title><p>Welcome!</p>' : LOGIN_PAGE);
  });
  await new Promise((r) => site.listen(0, '127.0.0.1', r));
  siteURL = `http://127.0.0.1:${site.address().port}`;
  browser = await puppeteer.launch({ browser: 'firefox', executablePath: FIREFOX, headless: true,
    extraPrefsFirefox: { 'extensions.webextensions.uuids': JSON.stringify({ 'storii@base2.sh': UUID }) } });
  await browser.installExtension(EXT);
});

after(async () => {
  await browser?.close();
  site?.close();
});

// The picker lives in a closed shadow root, so click where it is drawn: just below the field.
async function pickFirst(page, selector) {
  await page.click(selector);
  const box = await (await page.$(selector)).boundingBox();
  await sleep(600);
  await page.mouse.click(box.x + 60, box.y + box.height + 22);
}

const value = (page, sel) => page.$eval(sel, (e) => e.value);

test('Firefox: register in the popup, autofill, save prompt, lock', { timeout: 180000 }, async (t) => {
  if (skip) return t.skip(skip);
  const popup = await browser.newPage();
  // The popup re-renders after saves and syncs: retry a click that hit an element that was just replaced.
  const click = async (sel) => {
    for (let i = 0; ; i++) {
      try {
        return await popup.click(sel);
      } catch (e) {
        if (i > 10 || !/detached/i.test(e.message)) throw e;
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  };
  // Firefox doesn't report the load of extension pages over BiDi; the page is there regardless.
  await popup.goto(`moz-extension://${UUID}/popup/popup.html`, { timeout: 5000 }).catch(() => {});
  await popup.waitForSelector('#switch');
  await click('#switch');
  for (const [sel, v] of [['#server', SERVER], ['#user', USER], ['#pw', MASTER], ['#pw2', MASTER]]) await popup.type(sel, v);
  await click('#go');
  await popup.waitForSelector('#q', { timeout: 60000 });

  await click('#ctxs');
  await click('#add');
  await popup.type('#name', 'Example');
  await popup.type('#urls', siteURL);
  await click('#save');
  await new Promise((r) => setTimeout(r, 400)); // saving re-renders the list; don't click the old #back
  await click('#back');
  await click('#add');
  await popup.type('#name', 'Example login');
  await popup.type('[data-f=username]', 'me@example.com');
  await popup.type('[data-f=password]', 'hunter2-example');
  await popup.evaluate(() => {
    const s = document.querySelector('#ctxpick');
    s.value = [...s.options].find((o) => o.text === 'Example').value;
    s.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await click('#save');
  await popup.waitForSelector('#edit');

  const page = await browser.newPage();
  await page.goto(siteURL);
  await pickFirst(page, 'input[name=email]');
  await page.waitForFunction(() => document.querySelector('input[name=pass]').value !== '', { timeout: 10000 });
  assert.equal(await value(page, 'input[name=email]'), 'me@example.com');
  assert.equal(await value(page, 'input[name=pass]'), 'hunter2-example');

  // A new login is offered for saving after submitting; the save bar's Save button is top right.
  await page.goto(siteURL);
  await page.type('input[name=email]', 'other@example.com');
  await page.type('input[name=pass]', 'brand-new-pass');
  await Promise.all([page.waitForNavigation(), page.click('button[type=submit]')]);
  await sleep(1000);
  const width = await page.evaluate(() => innerWidth);
  await page.mouse.click(width - 12 - 40, 12 + 70);
  await sleep(1000);
  const items = await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'items' }, (x) => r(x.result))));
  assert.ok(items.find((i) => i.kind === 'secret' && i.fields?.username === 'other@example.com' && i.fields.password === 'brand-new-pass'),
    'the submitted login was saved');

  // Locked: nothing is filled.
  await popup.evaluate(() => new Promise((r) => chrome.runtime.sendMessage({ type: 'lock' }, r)));
  await page.goto(siteURL);
  await pickFirst(page, 'input[name=email]');
  await sleep(800);
  assert.equal(await value(page, 'input[name=pass]'), '');
});
