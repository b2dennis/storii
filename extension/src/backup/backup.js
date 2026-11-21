// Downloading and restoring encrypted backups, in a tab of its own (the toolbar popup closes while a file dialog is
// open). The service worker does the crypto: the backup password and the file's text go to it, plaintext never leaves.
import { isBackup } from '../lib/backup.js';

function call(type, msg = {}) {
  return new Promise((resolve, reject) =>
    chrome.runtime.sendMessage({ type, ...msg }, (r) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      r?.error ? reject(new Error(r.error)) : resolve(r?.result);
    }));
}

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const MAX_BYTES = 50 << 20;
let text = null;

async function unlocked() {
  const st = await call('status');
  const ok = st.configured && st.unlocked && !st.expired;
  $('locked').hidden = ok;
  $('main').hidden = !ok;
  return ok;
}

// Same rule as the master password (12+ characters, three kinds); the backup is only as strong as its password.
function weak(pw) {
  const kinds = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(pw)).length;
  return [...pw].length < 12 || kinds < 3;
}

$('export').onsubmit = async (e) => {
  e.preventDefault();
  $('exportErr').textContent = $('exported').textContent = '';
  const pw = $('pw').value;
  if (weak(pw)) return void ($('exportErr').textContent = 'Use at least 12 characters and three of: lowercase, uppercase, digits, symbols.');
  if (pw !== $('pw2').value) return void ($('exportErr').textContent = 'The passwords don’t match.');
  if (!(await unlocked())) return;
  $('download').disabled = true;
  $('download').textContent = 'Encrypting…';
  try {
    const file = await call('backup', { password: pw });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([file + '\n'], { type: 'application/json' }));
    a.download = `storii-backup-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    $('pw').value = $('pw2').value = '';
    $('exported').textContent = `Saved ${a.download}. Without the backup password it can’t be opened.`;
  } catch (err) {
    $('exportErr').textContent = err.message;
  } finally {
    $('download').disabled = false;
    $('download').textContent = 'Download backup';
  }
};

$('file').onchange = async () => {
  const f = $('file').files[0];
  $('restoreErr').textContent = $('restored').textContent = '';
  $('summary').hidden = $('go').hidden = true;
  text = null;
  if (!f) return;
  const t = f.size <= MAX_BYTES ? await f.text() : '';
  if (!isBackup(t)) {
    $('restore').hidden = true;
    $('restoreErr').textContent = 'That isn’t a storii backup. Other password managers’ exports go through Import.';
    return;
  }
  text = t;
  $('restore').hidden = false;
  $('rpw').focus();
};

$('restore').onsubmit = async (e) => {
  e.preventDefault();
  $('restoreErr').textContent = '';
  if (!text || !(await unlocked())) return;
  $('check').disabled = true;
  try {
    const plan = await call('restoreBackup', { password: $('rpw').value, text, dryRun: true });
    $('summary').innerHTML = `<b>${plan.added.length} to restore</b><span>${plan.skipped} already in storii</span>` +
      (plan.added.length ? `<span class="muted small">${plan.added.slice(0, 30).map(esc).join(', ')}${plan.added.length > 30 ? ', …' : ''}</span>` : '');
    $('summary').hidden = false;
    $('go').hidden = !plan.added.length;
    $('go').textContent = `Restore ${plan.added.length} item${plan.added.length === 1 ? '' : 's'}`;
  } catch (err) {
    $('restoreErr').textContent = err.message;
  } finally {
    $('check').disabled = false;
  }
};

$('go').onclick = async () => {
  $('go').disabled = true;
  try {
    const r = await call('restoreBackup', { password: $('rpw').value, text });
    $('restored').textContent = `Restored ${r.added.length} item${r.added.length === 1 ? '' : 's'}; ${r.skipped} already in storii.`;
    $('go').hidden = $('summary').hidden = $('restore').hidden = true;
    $('rpw').value = $('file').value = '';
    text = null;
  } catch (err) {
    $('restoreErr').textContent = err.message;
  } finally {
    $('go').disabled = false;
  }
};

$('unlock').onclick = () => call('openUnlock');
addEventListener('focus', () => { if (!$('locked').hidden) unlocked(); });
unlocked().catch(() => { $('locked').hidden = false; $('main').hidden = true; });
