// Managing shares, in a tab of its own. The service worker does the crypto; this page only shows names and asks.
function call(type, msg = {}) {
  return new Promise((resolve, reject) =>
    chrome.runtime.sendMessage({ type, ...msg }, (r) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      r?.error ? reject(new Error(r.error)) : resolve(r?.result);
    }));
}

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const pending = {}; // share id -> { username, public_key, fingerprint } waiting for confirmation

async function guarded(fn) {
  $('err').textContent = '';
  try {
    await fn();
  } catch (e) {
    $('err').textContent = e.message;
  }
  await render();
}

async function render() {
  const st = await call('status');
  const ok = st.configured && st.unlocked && !st.expired;
  $('locked').hidden = ok;
  $('main').hidden = !ok;
  if (!ok) return;
  const [{ fingerprint, shares, username }, items] = await Promise.all([call('shares'), call('items')]);
  $('fp').textContent = fingerprint || 'not set up (the server may be too old)';
  const secrets = items.filter((i) => i.kind === 'secret').sort((a, b) => a.name.localeCompare(b.name));
  $('shares').innerHTML = shares.map((s) => {
    const inside = secrets.filter((i) => i.share === s.id);
    const outside = secrets.filter((i) => !i.share);
    const p = pending[s.id];
    return `<div class="card share" data-share="${s.id}">
      <h2>${esc(s.name)} <span class="muted small">${s.mine ? 'yours' : `owned by ${esc(s.owner)}`}</span></h2>
      <div class="muted small">Members: ${s.members.map((m) => `<span class="chip">${esc(m.username)}${m.owner ? ' (owner)' : ''}${
        s.mine && !m.owner ? ` <button class="icon" data-remove="${esc(m.username)}" title="Remove">×</button>` : ''}</span>`).join(' ')}</div>
      ${s.mine ? (p ? `<div class="confirm"><p>${esc(p.username)}’s key fingerprint:<br><b>${esc(p.fingerprint)}</b></p>
          <p class="muted small">Ask ${esc(p.username)} to open Sharing (or run <code>storii share</code>) and read theirs. Only add them if it matches.</p>
          <div class="row"><button class="primary" data-confirm>It matches, add ${esc(p.username)}</button><button data-cancel>Cancel</button></div></div>`
        : `<form class="row" data-add><input name="user" placeholder="Username to add" required><button type="submit">Add…</button></form>`) : ''}
      <h3 class="small">Secrets (${inside.length})</h3>
      <ul>${inside.map((i) => `<li>${esc(i.name)} <button class="link" data-home="${i.id}">Move to my vault</button></li>`).join('') || '<li class="muted">none yet</li>'}</ul>
      ${outside.length ? `<form class="row" data-move><select name="item">${outside.map((i) => `<option value="${i.id}">${esc(i.name)}</option>`).join('')}</select>
        <button type="submit">Move into ${esc(s.name)}</button></form>` : ''}
      <div class="row">${s.mine ? `<button data-rename>Rename…</button><button class="danger" data-delete>Delete share</button>`
        : `<button class="danger" data-leave>Leave share</button>`}</div>
    </div>`;
  }).join('') || '<p class="muted">No shares yet.</p>';
  for (const el of document.querySelectorAll('[data-share]')) {
    const id = el.dataset.share;
    const s = shares.find((x) => x.id === id);
    el.querySelector('[data-add]')?.addEventListener('submit', (e) => {
      e.preventDefault();
      guarded(async () => {
        const who = e.target.user.value.trim();
        if (who.toLowerCase() === username.toLowerCase()) throw new Error('You are already in it.');
        pending[id] = await call('memberKey', { username: who });
      });
    });
    el.querySelector('[data-confirm]')?.addEventListener('click', () => guarded(async () => {
      const p = pending[id];
      delete pending[id];
      await call('addMember', { id, username: p.username, publicKey: p.public_key });
    }));
    el.querySelector('[data-cancel]')?.addEventListener('click', () => guarded(async () => { delete pending[id]; }));
    el.querySelectorAll('[data-remove]').forEach((b) => b.addEventListener('click', () => {
      if (confirm(`Remove ${b.dataset.remove} from ${s.name}? They keep anything they already copied: change those passwords if that matters.`)) {
        guarded(() => call('removeMember', { id, username: b.dataset.remove }));
      }
    }));
    el.querySelectorAll('[data-home]').forEach((b) => b.addEventListener('click', () => guarded(() => call('moveItems', { ids: [b.dataset.home], share: '' }))));
    el.querySelector('[data-move]')?.addEventListener('submit', (e) => {
      e.preventDefault();
      guarded(() => call('moveItems', { ids: [e.target.item.value], share: id }));
    });
    el.querySelector('[data-rename]')?.addEventListener('click', () => {
      const name = prompt('New name', s.name);
      if (name?.trim()) guarded(() => call('renameShare', { id, name }));
    });
    el.querySelector('[data-delete]')?.addEventListener('click', () => {
      if (confirm(`Delete ${s.name} and its secrets for every member?`)) guarded(() => call('deleteShare', { id }));
    });
    el.querySelector('[data-leave]')?.addEventListener('click', () => {
      if (confirm(`Leave ${s.name}? Its secrets disappear from your vault.`)) guarded(() => call('deleteShare', { id }));
    });
  }
}

$('create').onsubmit = (e) => {
  e.preventDefault();
  guarded(async () => {
    await call('createShare', { name: $('newName').value });
    $('newName').value = '';
  });
};
$('unlock').onclick = () => call('openUnlock');
document.addEventListener('visibilitychange', () => document.visibilityState === 'visible' && render());
render().catch((e) => ($('err').textContent = e.message));
