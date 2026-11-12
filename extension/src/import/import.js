// Importing a browser's password export (CSV) into storii, in a tab of its own: the toolbar popup would close while
// the file dialog is open. The file is read here; the plan is made against the decrypted vault and saved through the
// service worker, which encrypts every item before it leaves the browser.
import { parseCsv, buildImport, NotAnExport } from '../lib/importcsv.js';

function call(type, msg = {}) {
  return new Promise((resolve, reject) =>
    chrome.runtime.sendMessage({ type, ...msg }, (r) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      r?.error ? reject(new Error(r.error)) : resolve(r?.result);
    }));
}

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const n = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;
const MAX_BYTES = 20 << 20;
let plan = null;

function show(id) {
  for (const s of ['locked', 'start', 'ready', 'done']) $(s).hidden = s !== id;
}

// Open the instructions for the browser this page runs in.
const ua = navigator.userAgent;
const browser = /Firefox\//.test(ua) ? 'firefox' : /Edg\//.test(ua) ? 'edge' : /Chrome\//.test(ua) ? 'chrome' : '';
if (browser) $(`b-${browser}`).open = true;

async function unlocked() {
  const st = await call('status');
  if (!st.configured || !st.unlocked || st.expired) {
    show('locked');
    return false;
  }
  return true;
}

async function load(file) {
  $('err').textContent = '';
  if (!(await unlocked())) return;
  try {
    if (file.size > MAX_BYTES) throw new NotAnExport('That file is too big for a password export.');
    const rows = parseCsv(await file.text());
    const items = Object.fromEntries((await call('items')).map(({ id, ...it }) => [id, it]));
    plan = { ...buildImport(items, rows, () => crypto.randomUUID()), rows: rows.length };
  } catch (e) {
    $('file').value = '';
    $('err').textContent = e instanceof NotAnExport ? e.message : `Couldn’t read that file: ${e.message}`;
    return;
  }
  const count = (a) => plan.lines.filter((l) => l.action === a).length;
  const add = count('add'), users = count('username'), differs = plan.lines.filter((l) => l.differs).length;
  $('summary').innerHTML = `<b>${n(plan.rows, 'login')} in the file</b>
    <span>${add} new</span>
    ${users ? `<span>${n(users, 'username')} filled in (for logins that had none)</span>` : ''}
    <span>${count('skip')} already in storii</span>
    ${count('invalid') ? `<span>${count('invalid')} without a password, left out</span>` : ''}
    ${differs ? `<span class="muted small">${n(differs, 'login')} with a different password for the same site and username: both are kept, so check which one is current afterwards.</span>` : ''}`;
  $('go').hidden = add + users === 0;
  $('go').textContent = add ? `Import ${n(add, 'login')}` : `Fill in ${n(users, 'username')}`;
  $('lines').innerHTML = plan.lines.filter((l) => l.action === 'add' || l.action === 'username').map((l) => `<li>${esc(l.name)}
    <div class="muted small">${[l.site && l.site !== l.name ? esc(l.site) : '', l.action === 'username' ? 'fills in the username'
      : l.differs ? 'new · another password for this login is kept too' : 'new'].filter(Boolean).join(' · ')}</div></li>`).join('');
  if (add + users === 0) $('lines').innerHTML = '<li>Everything in this file is already in storii.</li>';
  show('ready');
}

$('file').onchange = () => $('file').files[0] && load($('file').files[0]);
$('cancel').onclick = () => { plan = null; $('file').value = ''; show('start'); };
$('go').onclick = async () => {
  $('go').disabled = true;
  try {
    await call('saveMany', { changes: [...plan.writes].map(([id, item]) => ({ id, item })) });
    const add = plan.lines.filter((l) => l.action === 'add').length, users = plan.lines.filter((l) => l.action === 'username').length;
    $('result').textContent = `Imported ${n(add, 'login')}${users ? ` and filled in ${n(users, 'username')}` : ''}.`;
    plan = null;
    $('file').value = '';
    show('done');
  } catch (e) {
    $('summary').insertAdjacentHTML('beforeend', `<span class="err">Import failed: ${esc(e.message)}</span>`);
  } finally {
    $('go').disabled = false;
  }
};
$('unlock').onclick = () => call('openUnlock');
$('close').onclick = () => window.close();
// Back from unlocking in the popup or a storii window.
addEventListener('focus', async () => { if (!$('locked').hidden && (await unlocked())) show('start'); });

unlocked().catch(() => show('locked'));
