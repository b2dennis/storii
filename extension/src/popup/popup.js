import { totpFromFields, totpFields, totpCode, totpRemaining, parseOtpauth } from '../lib/totp.js';
import { host as hostOf, contextMatches } from '../lib/match.js';

const app = document.getElementById('app');
if (new URLSearchParams(location.search).has('window')) document.body.classList.add('window');

const TYPES = { password: 'Password', totp: '2FA code', api_key: 'API key', note: 'Note' };
const BADGE = { password: '••', totp: '2F', api_key: '{}', note: '¶' };

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

function call(type, msg = {}) {
  return new Promise((resolve, reject) =>
    chrome.runtime.sendMessage({ type, ...msg }, (r) => {
      if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
      r?.error ? reject(new Error(r.error)) : resolve(r?.result);
    }));
}

let toastTimer;
function toast(text) {
  const t = document.getElementById('toast');
  t.textContent = text;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 1600);
}

async function copy(text, what) {
  await navigator.clipboard.writeText(text);
  toast(`${what} copied`);
  // Clear it later if it is still ours. The popup may be closed by then; that is fine, the copy is best effort.
  setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('');
    } catch { /* no focus any more */ }
  }, 30000);
}

const ui = { items: [], tab: null, query: '', view: 'list', editing: null, timer: null };

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab && /^https?:/.test(tab.url || '') ? tab : null;
}

const secrets = () => ui.items.filter((i) => i.kind === 'secret');
const contexts = () => ui.items.filter((i) => i.kind === 'context').sort((a, b) => a.name.localeCompare(b.name));
const byId = (id) => ui.items.find((i) => i.id === id);

function subtitle(s) {
  if (s.type === 'password') return s.fields?.username || '';
  if (s.type === 'totp') return [s.fields?.issuer, s.fields?.account].filter(Boolean).join(' · ');
  if (s.type === 'api_key') return s.fields?.key_id || 'API key';
  return (s.notes || '').split('\n')[0];
}

function siteSecrets() {
  const h = ui.tab ? hostOf(ui.tab.url) : '';
  if (!h) return [];
  const ctx = new Set(contexts().filter((c) => contextMatches(c, h)).map((c) => c.id));
  return secrets().filter((s) => s.contexts?.some((c) => ctx.has(c)));
}

// Views.

async function render() {
  clearInterval(ui.timer);
  const st = await call('status');
  if (!st.configured) return renderSetup();
  if (!st.unlocked || st.expired) return renderLocked(st);
  try {
    ui.items = await call('items');
  } catch {
    return renderLocked(st);
  }
  ui.tab ||= await currentTab();
  if (ui.view === 'edit') return renderEdit();
  if (ui.view === 'detail') return renderDetail();
  if (ui.view === 'contexts') return renderContexts();
  if (ui.view === 'context') return renderContextEdit();
  if (ui.view === 'settings') return renderSettings(st);
  return renderList(st);
}

function renderSetup(register = false) {
  app.innerHTML = `<div class="center">
    <h2>${register ? 'Create a storii account' : 'Log in to storii'}</h2>
    <p class="muted small">Your master password never leaves this device. Without it nobody, including the server, can read your vault.</p>
    <label>Server<input id="server" placeholder="https://storii.example.com" autocomplete="url"></label>
    <label>Username<input id="user" autocomplete="username"></label>
    <label>Master password<input id="pw" type="password" autocomplete="${register ? 'new-password' : 'current-password'}"></label>
    ${register ? '<label>Repeat master password<input id="pw2" type="password" autocomplete="new-password"></label>' : ''}
    <div class="err" id="err"></div>
    <button class="primary" id="go">${register ? 'Create account' : 'Log in'}</button>
    <button class="link" id="switch">${register ? 'I already have an account' : 'Create an account instead'}</button>
  </div>`;
  const $ = (id) => document.getElementById(id);
  $('switch').onclick = () => renderSetup(!register);
  const go = async () => {
    const pw = $('pw').value;
    if (register) {
      if (pw !== $('pw2').value) return ($('err').textContent = 'The passwords don’t match.');
      if (pw.length < 12) return ($('err').textContent = 'Use at least 12 characters.');
    }
    $('go').disabled = true;
    $('err').textContent = '';
    $('go').textContent = 'Deriving keys…';
    try {
      await call('login', { server: $('server').value, username: $('user').value.trim(), password: pw, register });
      render();
    } catch (e) {
      $('err').textContent = e.message;
      $('go').disabled = false;
      $('go').textContent = register ? 'Create account' : 'Log in';
    }
  };
  $('go').onclick = go;
  app.querySelectorAll('input').forEach((i) => i.addEventListener('keydown', (e) => e.key === 'Enter' && go()));
  $('server').focus();
}

function renderLocked(st) {
  if (st.expired) {
    app.innerHTML = `<div class="center"><h2>Session ended</h2>
      <p class="muted">This browser was signed out of ${esc(st.server)} (master password changed or session revoked).</p>
      <button class="primary" id="again">Log in again</button></div>`;
    document.getElementById('again').onclick = async () => {
      await call('logout');
      renderSetup();
      document.getElementById('server').value = st.server;
      document.getElementById('user').value = st.username;
      document.getElementById('pw').focus();
    };
    return;
  }
  app.innerHTML = `<div class="center">
    <h2>storii is locked</h2>
    <p class="muted small">${esc(st.username)} · ${esc(st.server)}</p>
    <label>Master password<input id="pw" type="password" autocomplete="current-password" autofocus></label>
    <div class="err" id="err"></div>
    <button class="primary" id="go">Unlock</button>
    <button class="link" id="out">Log out of this browser</button>
  </div>`;
  const pw = document.getElementById('pw');
  const go = async () => {
    document.getElementById('go').disabled = true;
    try {
      await call('unlock', { password: pw.value });
      if (document.body.classList.contains('window')) return window.close();
      render();
    } catch (e) {
      document.getElementById('err').textContent = e.message;
      document.getElementById('go').disabled = false;
      pw.select();
    }
  };
  document.getElementById('go').onclick = go;
  pw.addEventListener('keydown', (e) => e.key === 'Enter' && go());
  document.getElementById('out').onclick = async () => {
    if (confirm('Log out? The local copy of the vault is removed from this browser.')) {
      await call('logout');
      render();
    }
  };
  pw.focus();
}

function header(title, extra = '') {
  return `<header><h1>${title}</h1>${extra}</header>`;
}

async function renderList(st) {
  const pending = ui.tab ? await call('pendingForTab', { tabId: ui.tab.id }) : null;
  app.innerHTML = header(`storii<small>${esc(st.username)}</small>`, `
      <button class="icon" id="add" title="Add a secret">＋</button>
      <button class="icon" id="ctxs" title="Contexts">⌂</button>
      <button class="icon" id="sync" title="Sync">⟳</button>
      <button class="icon" id="settings" title="Settings">⚙</button>
      <button class="icon" id="lock" title="Lock">🔒</button>`) +
    `<div class="pad" style="padding-bottom:0"><input id="q" type="search" placeholder="Search secrets and contexts" value="${esc(ui.query)}"></div>
    ${pending ? `<div class="banner"><b>${pending.existingId ? 'Update' : 'Save'} the login for ${esc(pending.host)}?</b>
      <div class="muted small">${esc(pending.username || 'no username')}</div>
      <div class="row" style="margin-top:8px"><button id="pdiscard">Not now</button><button class="primary" id="psave">Save</button></div></div>` : ''}
    <div id="lists"></div>`;
  const $ = (id) => document.getElementById(id);
  $('add').onclick = () => openEdit(null);
  $('ctxs').onclick = () => { ui.view = 'contexts'; render(); };
  $('settings').onclick = () => { ui.view = 'settings'; render(); };
  $('lock').onclick = async () => { await call('lock'); render(); };
  $('sync').onclick = async () => {
    try {
      await call('sync');
      toast('Up to date');
    } catch (e) {
      toast(e.message);
    }
    render();
  };
  if (pending) {
    $('psave').onclick = async () => { await call('savePendingForTab', { tabId: ui.tab.id }); toast('Saved'); render(); };
    $('pdiscard').onclick = async () => { await call('savePendingForTab', { tabId: ui.tab.id, discard: true }); render(); };
  }
  const q = $('q');
  q.oninput = () => { ui.query = q.value; drawLists(); };
  q.focus();
  drawLists();
  ui.timer = setInterval(updateCodes, 1000);
}

function rowHtml(s, fill) {
  const isTotp = s.type === 'totp';
  return `<div class="item" data-id="${s.id}">
    <div class="badge">${BADGE[s.type] || '?'}</div>
    <div class="main"><div class="name">${esc(s.name)}</div><div class="sub">${esc(subtitle(s))}</div></div>
    ${isTotp ? `<span class="code" data-code="${s.id}"></span><span class="ring" data-ring="${s.id}"></span>` : ''}
    ${fill && (s.type === 'password' || isTotp) ? `<button class="icon" data-fill="${s.id}" title="Fill on this page">↧</button>` : ''}
    ${s.type !== 'note' ? `<button class="icon" data-copy="${s.id}" title="Copy">⧉</button>` : ''}
  </div>`;
}

function drawLists() {
  const q = ui.query.trim().toLowerCase();
  const ctxName = (s) => (s.contexts || []).map((c) => byId(c)?.name || '').join(' ');
  const match = (s) => !q || `${s.name} ${subtitle(s)} ${ctxName(s)} ${TYPES[s.type]}`.toLowerCase().includes(q);
  const site = siteSecrets().filter(match);
  const siteIds = new Set(site.map((s) => s.id));
  const rest = secrets().filter((s) => match(s) && !siteIds.has(s.id)).sort((a, b) => a.name.localeCompare(b.name));
  let html = '';
  if (ui.tab && hostOf(ui.tab.url)) {
    html += `<div class="section">This site · ${esc(hostOf(ui.tab.url))}</div><div class="list">${
      site.length ? site.map((s) => rowHtml(s, true)).join('') : '<div class="muted small" style="padding:6px 8px">Nothing saved for this site.</div>'}</div>`;
  }
  html += `<div class="section">${q ? 'Results' : 'All secrets'}</div><div class="list">${rest.map((s) => rowHtml(s, false)).join('') ||
    (secrets().length ? '<div class="empty">No matches.</div>' : '<div class="empty">Your vault is empty. Add a password, 2FA code or API key with ＋.</div>')}</div>`;
  const lists = document.getElementById('lists');
  lists.innerHTML = html;
  lists.querySelectorAll('.item').forEach((el) => (el.onclick = () => { ui.editing = el.dataset.id; ui.view = 'detail'; render(); }));
  lists.querySelectorAll('[data-copy]').forEach((b) => (b.onclick = async (e) => {
    e.stopPropagation();
    const s = byId(b.dataset.copy);
    if (s.type === 'totp') return copy(await totpCode(totpFromFields(s.fields)), '2FA code');
    copy(s.type === 'api_key' ? s.fields.key : s.fields.password, TYPES[s.type]);
  }));
  lists.querySelectorAll('[data-fill]').forEach((b) => (b.onclick = async (e) => {
    e.stopPropagation();
    try {
      await call('fillTab', { tabId: ui.tab.id, id: b.dataset.fill });
      window.close();
    } catch (err) {
      toast('Can’t fill this page: ' + err.message);
    }
  }));
  updateCodes();
}

async function updateCodes() {
  for (const el of document.querySelectorAll('[data-code]')) {
    try {
      const t = totpFromFields(byId(el.dataset.code).fields);
      const code = await totpCode(t);
      el.textContent = code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
      const ring = document.querySelector(`[data-ring="${el.dataset.code}"]`);
      if (ring) ring.textContent = `${totpRemaining(t)}s`;
    } catch {
      el.textContent = 'invalid';
    }
  }
}

function field(k, v, { secret = false, copyable = true, what = k } = {}) {
  return `<div class="detail-field"><span class="k">${esc(k)}</span>
    <span class="v" ${secret ? `data-secret="${esc(v)}"` : ''}>${secret ? '••••••••' : esc(v)}</span>
    ${secret ? '<button class="icon" data-reveal title="Show">👁</button>' : ''}
    ${copyable ? `<button class="icon" data-copyval="${esc(v)}" data-what="${esc(what)}" title="Copy">⧉</button>` : ''}</div>`;
}

function renderDetail() {
  const s = byId(ui.editing);
  if (!s) { ui.view = 'list'; return render(); }
  let body = '';
  const f = s.fields || {};
  if (s.type === 'password') {
    if (f.username) body += field('Username', f.username);
    body += field('Password', f.password || '', { secret: true });
  } else if (s.type === 'totp') {
    body += `<div class="detail-field"><span class="k">Code</span><span class="v"><span class="code" data-code="${s.id}"></span>
      <span class="ring" data-ring="${s.id}"></span></span><button class="icon" id="copycode" title="Copy">⧉</button></div>`;
    if (f.issuer) body += field('Issuer', f.issuer);
    if (f.account) body += field('Account', f.account);
  } else if (s.type === 'api_key') {
    if (f.key_id) body += field('Key ID', f.key_id);
    body += field('Key', f.key || '', { secret: true });
  }
  const known = ['username', 'password', 'secret', 'issuer', 'account', 'algorithm', 'digits', 'period', 'key', 'key_id'];
  for (const [k, v] of Object.entries(f)) if (!known.includes(k)) body += field(k, v);
  for (const c of s.custom || []) body += field(c.name, c.value, { secret: c.hidden });
  if (s.notes) body += `<div class="detail-field"><span class="k">Notes</span><span class="v" style="white-space:pre-wrap">${esc(s.notes)}</span></div>`;
  const ctxs = (s.contexts || []).map(byId).filter(Boolean);
  body += `<div class="detail-field"><span class="k">Contexts</span><span class="v chips">${
    ctxs.map((c) => `<span class="chip" style="padding-right:9px">${esc(c.name)}</span>`).join('') || '<span class="muted">none</span>'}</span></div>`;
  app.innerHTML = header(`<button class="icon" id="back">‹</button> ${esc(s.name)}`, `<button id="edit">Edit</button>`) +
    `<div class="pad"><div class="muted small">${TYPES[s.type] || s.type}</div>${body}</div>`;
  document.getElementById('back').onclick = () => { ui.view = 'list'; render(); };
  document.getElementById('edit').onclick = () => openEdit(s.id);
  app.querySelectorAll('[data-copyval]').forEach((b) => (b.onclick = () => copy(b.dataset.copyval, b.dataset.what)));
  app.querySelectorAll('[data-reveal]').forEach((b) => (b.onclick = () => {
    const v = b.previousElementSibling;
    v.textContent = v.textContent.startsWith('•') ? v.dataset.secret : '••••••••';
  }));
  document.getElementById('copycode')?.addEventListener('click', async () => copy(await totpCode(totpFromFields(f)), '2FA code'));
  updateCodes();
  ui.timer = setInterval(updateCodes, 1000);
}

function generate(n = 20) {
  const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789', '!@#$%^&*.()'];
  const all = sets.join('');
  for (;;) {
    const r = crypto.getRandomValues(new Uint32Array(n));
    const p = [...r].map((x) => all[x % all.length]).join('');
    if (sets.every((s) => [...p].some((c) => s.includes(c)))) return p;
  }
}

function openEdit(id) {
  ui.editing = id;
  ui.draft = null;
  ui.view = 'edit';
  render();
}

function renderEdit() {
  const existing = ui.editing ? byId(ui.editing) : null;
  const d = (ui.draft ||= existing ? structuredClone(existing) : {
    kind: 'secret', type: 'password', name: ui.tab ? hostOf(ui.tab.url) : '', fields: {},
    contexts: [], _siteContext: !!ui.tab,
  });
  const f = d.fields;
  const typeFields = {
    password: `<label>Username<input data-f="username" value="${esc(f.username)}" autocomplete="off"></label>
      <label>Password<div class="row"><input data-f="password" value="${esc(f.password)}" type="password" autocomplete="new-password">
      <button class="fixed" id="gen" type="button" title="Generate">⚄</button><button class="fixed" id="show" type="button" title="Show">👁</button></div></label>`,
    totp: `<label>Setup key or otpauth:// link<input id="totpin" value="${esc(f.secret)}" placeholder="JBSW Y3DP EHPK 3PXP or otpauth://totp/…" autocomplete="off"></label>
      <div class="row"><label>Issuer<input data-f="issuer" value="${esc(f.issuer)}"></label><label>Account<input data-f="account" value="${esc(f.account)}"></label></div>
      <div class="muted small" id="totppreview"></div>`,
    api_key: `<label>Key<input data-f="key" value="${esc(f.key)}" type="password" autocomplete="off"></label>
      <label>Key ID (optional)<input data-f="key_id" value="${esc(f.key_id)}"></label>`,
    note: '',
  };
  const linked = d.contexts.map(byId).filter(Boolean);
  const siteHost = ui.tab ? hostOf(ui.tab.url) : '';
  const siteCtx = siteHost && contexts().find((c) => (c.urls || []).some((u) => hostOf(u) === siteHost));
  app.innerHTML = header(`<button class="icon" id="back">‹</button> ${existing ? 'Edit' : 'New secret'}`) + `<div class="form">
    <label>Type<select id="type" ${existing ? 'disabled' : ''}>${Object.entries(TYPES).map(([k, v]) =>
      `<option value="${k}" ${d.type === k ? 'selected' : ''}>${v}</option>`).join('')}</select></label>
    <label>Name<input id="name" value="${esc(d.name)}"></label>
    ${typeFields[d.type]}
    <label>Notes<textarea id="notes">${esc(d.notes)}</textarea></label>
    <div><div class="muted small" style="margin-bottom:6px">Contexts (apps and websites this belongs to)</div>
      <div class="chips">${linked.map((c) => `<span class="chip">${esc(c.name)}<button data-unlink="${c.id}" title="Remove">×</button></span>`).join('')}
      ${d._siteContext && siteHost && !siteCtx ? `<span class="chip">${esc(siteHost)} (new)<button id="nosite" title="Remove">×</button></span>` : ''}</div>
      <div class="row" style="margin-top:6px"><select id="ctxpick"><option value="">Add a context…</option>
        ${siteHost && !siteCtx && !d._siteContext ? `<option value="__site">This site (${esc(siteHost)})</option>` : ''}
        ${contexts().filter((c) => !d.contexts.includes(c.id)).map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join('')}
        <option value="__new">New context…</option></select></div></div>
    <div class="err" id="err"></div>
    <div class="row">${existing ? '<button class="danger fixed" id="del">Delete</button>' : ''}<button class="primary" id="save">Save</button></div>
  </div>`;
  const $ = (id) => document.getElementById(id);
  // Keep the draft in sync with the inputs, so re-rendering (type change, contexts) loses nothing.
  const collect = () => {
    d.name = $('name').value;
    d.notes = $('notes').value;
    app.querySelectorAll('[data-f]').forEach((i) => (f[i.dataset.f] = i.value));
    if ($('totpin')) f.secret = $('totpin').value;
  };
  if (!existing && siteCtx && !d.contexts.includes(siteCtx.id) && d._siteContext) {
    d.contexts.push(siteCtx.id);
    d._siteContext = false;
    return renderEdit();
  }
  $('back').onclick = () => { ui.view = existing ? 'detail' : 'list'; render(); };
  $('type').onchange = () => { collect(); d.type = $('type').value; renderEdit(); };
  $('gen')?.addEventListener('click', () => { const i = app.querySelector('[data-f=password]'); i.value = generate(); i.type = 'text'; });
  $('show')?.addEventListener('click', () => { const i = app.querySelector('[data-f=password]'); i.type = i.type === 'password' ? 'text' : 'password'; });
  $('nosite')?.addEventListener('click', () => { collect(); d._siteContext = false; renderEdit(); });
  app.querySelectorAll('[data-unlink]').forEach((b) => (b.onclick = () => {
    collect();
    d.contexts = d.contexts.filter((c) => c !== b.dataset.unlink);
    renderEdit();
  }));
  $('ctxpick').onchange = () => {
    collect();
    const v = $('ctxpick').value;
    if (v === '__site') d._siteContext = true;
    else if (v === '__new') {
      ui.ctxReturn = 'edit';
      ui.ctxEditing = null;
      ui.view = 'context';
      return render();
    } else if (v) d.contexts.push(v);
    renderEdit();
  };
  const preview = async () => {
    const p = $('totppreview');
    if (!p) return;
    const v = $('totpin').value.trim();
    if (!v) return (p.textContent = '');
    try {
      const t = v.startsWith('otpauth://') ? parseOtpauth(v) : totpFromFields({ ...f, secret: v });
      p.textContent = `Current code: ${await totpCode(t)}`;
    } catch (e) {
      p.textContent = e.message;
    }
  };
  $('totpin')?.addEventListener('input', preview);
  preview();
  $('del')?.addEventListener('click', async () => {
    if (!confirm(`Delete ${existing.name}?`)) return;
    await call('delete', { ids: [existing.id] });
    ui.view = 'list';
    render();
  });
  $('save').onclick = async () => {
    collect();
    const err = $('err');
    err.textContent = '';
    const item = { kind: 'secret', type: d.type, name: d.name.trim(), contexts: [...d.contexts], fields: {}, notes: d.notes || undefined,
      custom: d.custom, created_at: d.created_at };
    for (const [k, v] of Object.entries(f)) if (v) item.fields[k] = v;
    if (d.type === 'totp') {
      try {
        const raw = (f.secret || '').trim();
        const t = raw.startsWith('otpauth://') ? parseOtpauth(raw) : totpFromFields({ ...f, secret: raw });
        if (f.issuer) t.issuer = f.issuer;
        if (f.account) t.account = f.account;
        item.fields = totpFields(t);
        if (!item.name) item.name = t.issuer || t.account;
      } catch (e) {
        return (err.textContent = e.message);
      }
    }
    if (!item.name) return (err.textContent = 'Give it a name.');
    const changes = [];
    if (d._siteContext && siteHost && !siteCtx) {
      const cid = crypto.randomUUID();
      changes.push({ id: cid, item: { kind: 'context', name: siteHost, context_type: 'website', urls: [`https://${siteHost}`] } });
      item.contexts.push(cid);
    }
    changes.push({ id: existing?.id, item });
    try {
      const ids = await call('saveMany', { changes });
      ui.editing = ids[ids.length - 1];
      ui.view = 'detail';
      toast('Saved');
      render();
    } catch (e) {
      err.textContent = e.message;
    }
  };
  $('name').focus();
}

function renderContexts() {
  const count = (c) => secrets().filter((s) => s.contexts?.includes(c.id)).length;
  app.innerHTML = header('<button class="icon" id="back">‹</button> Contexts', '<button class="icon" id="add" title="New context">＋</button>') +
    `<p class="pad muted small" style="margin:0">A context is an app or website. Secrets in a context are offered wherever it matches.</p>
    <div class="list">${contexts().map((c) => `<div class="item" data-id="${c.id}"><div class="badge">${c.context_type === 'app' ? '▣' : c.context_type === 'website' ? '◍' : '◇'}</div>
      <div class="main"><div class="name">${esc(c.name)}</div><div class="sub">${esc([...(c.urls || []), ...(c.android_packages || [])].join(', ') || 'no URLs')}</div></div>
      <span class="muted small">${count(c)}</span></div>`).join('') || '<div class="empty">No contexts yet.</div>'}</div>`;
  document.getElementById('back').onclick = () => { ui.view = 'list'; render(); };
  document.getElementById('add').onclick = () => { ui.ctxEditing = null; ui.ctxReturn = 'contexts'; ui.view = 'context'; render(); };
  app.querySelectorAll('.item').forEach((el) => (el.onclick = () => { ui.ctxEditing = el.dataset.id; ui.ctxReturn = 'contexts'; ui.view = 'context'; render(); }));
}

function renderContextEdit() {
  const c = ui.ctxEditing ? byId(ui.ctxEditing) : null;
  const siteHost = ui.tab ? hostOf(ui.tab.url) : '';
  const linked = c ? secrets().filter((s) => s.contexts?.includes(c.id)) : [];
  app.innerHTML = header(`<button class="icon" id="back">‹</button> ${c ? esc(c.name) : 'New context'}`) + `<div class="form">
    <label>Name<input id="name" value="${esc(c?.name || siteHost)}"></label>
    <label>Type<select id="type">${['website', 'app', 'other'].map((t) => `<option ${(c?.context_type || 'website') === t ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
    <label>Website URLs (one per line)<textarea id="urls">${esc((c?.urls || (siteHost ? [`https://${siteHost}`] : [])).join('\n'))}</textarea></label>
    <label>Android apps (package names, one per line)<textarea id="apps" placeholder="com.example.app">${esc((c?.android_packages || []).join('\n'))}</textarea></label>
    ${c ? `<div class="muted small">${linked.length ? 'Secrets: ' + linked.map((s) => esc(s.name)).join(', ') : 'No secrets in this context.'}</div>` : ''}
    <div class="err" id="err"></div>
    <div class="row">${c ? '<button class="danger fixed" id="del">Delete</button>' : ''}<button class="primary" id="save">Save</button></div></div>`;
  const $ = (id) => document.getElementById(id);
  const back = () => { ui.view = ui.ctxReturn || 'contexts'; render(); };
  $('back').onclick = back;
  $('del')?.addEventListener('click', async () => {
    if (!confirm(`Delete the context ${c.name}? Its secrets are kept.`)) return;
    await call('delete', { ids: [c.id] });
    back();
  });
  $('save').onclick = async () => {
    const lines = (id) => $(id).value.split('\n').map((s) => s.trim()).filter(Boolean);
    const item = { ...(c || {}), kind: 'context', name: $('name').value.trim(), context_type: $('type').value,
      urls: lines('urls'), android_packages: lines('apps') };
    delete item.id;
    if (!item.name) return ($('err').textContent = 'Give it a name.');
    const id = await call('save', { id: c?.id, item });
    if (ui.ctxReturn === 'edit' && ui.draft) ui.draft.contexts.push(id);
    back();
  };
}

async function renderSettings(st) {
  const s = await call('settings', {});
  app.innerHTML = header('<button class="icon" id="back">‹</button> Settings') + `<div class="form">
    <label>Lock after inactivity<select id="lock">${[1, 5, 15, 30, 60, 240, 0].map((m) =>
      `<option value="${m}" ${s.lockMinutes === m ? 'selected' : ''}>${m === 0 ? 'Only when the browser closes' : m < 60 ? `${m} minutes` : `${m / 60} hours`}</option>`).join('')}</select></label>
    <div class="muted small">Logged in as <b>${esc(st.username)}</b> on ${esc(st.server)}.</div>
    <div class="muted small">Keyboard shortcut to fill the current page: Ctrl+Shift+L (change it in the browser’s extension shortcut settings).</div>
    <button id="out" class="danger">Log out of this browser</button></div>`;
  document.getElementById('back').onclick = () => { ui.view = 'list'; render(); };
  document.getElementById('lock').onchange = (e) => call('settings', { set: { lockMinutes: Number(e.target.value) } }).then(() => toast('Saved'));
  document.getElementById('out').onclick = async () => {
    if (!confirm('Log out? The local copy of the vault is removed from this browser.')) return;
    await call('logout');
    ui.view = 'list';
    render();
  };
}

render();
