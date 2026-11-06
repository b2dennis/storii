// The background worker owns the vault: the encrypted copy in storage.local, and while unlocked the vault key in
// storage.session (memory only, gone when the browser closes). Content scripts only ever get the secrets of
// contexts that match the frame they run in.
import { deriveKeys, newKdf, randomBytes, toB64, fromB64, wrapVaultKey, unwrapVaultKey, encryptItem, decryptItem } from './lib/crypto.js';
import { contextMatches, host as hostOf } from './lib/match.js';
import { totpFromFields, totpCode } from './lib/totp.js';

const DEFAULT_LOCK_MINUTES = 15;

// Storage.

async function getState() {
  return (await chrome.storage.local.get('state')).state || null;
}

async function setState(state) {
  await chrome.storage.local.set({ state });
}

async function getSettings() {
  return { lockMinutes: DEFAULT_LOCK_MINUTES, ...(await chrome.storage.local.get('settings')).settings };
}

async function getVaultKey() {
  const { vaultKey } = await chrome.storage.session.get('vaultKey');
  return vaultKey ? fromB64(vaultKey) : null;
}

// Decrypted items, cached per worker lifetime and rebuilt on demand.
let cache = null; // Map id -> item

async function items() {
  if (cache) return cache;
  const key = await getVaultKey();
  const state = await getState();
  if (!key || !state) return null;
  cache = new Map();
  for (const [id, it] of Object.entries(state.items || {})) {
    try {
      cache.set(id, await decryptItem(key, id, it.data));
    } catch {
      console.warn('storii: could not decrypt item', id);
    }
  }
  return cache;
}

async function touch() {
  const { lockMinutes } = await getSettings();
  if (lockMinutes > 0) chrome.alarms.create('autolock', { delayInMinutes: lockMinutes });
}

async function lock() {
  cache = null;
  await chrome.storage.session.remove('vaultKey');
  chrome.alarms.clear('autolock');
  updateBadge();
}

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === 'autolock') lock();
  if (a.name === 'sync') sync().catch(() => {});
});
chrome.alarms.create('sync', { periodInMinutes: 5 });

async function updateBadge() {
  const unlocked = !!(await getVaultKey());
  chrome.action.setBadgeText({ text: unlocked ? '' : '•' });
  chrome.action.setBadgeBackgroundColor({ color: '#9a6b00' });
}

// Server.

async function api(state, method, path, body) {
  const res = await fetch(state.server + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(state.token ? { Authorization: `Bearer ${state.token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) {
    const err = new Error(data.error || `server answered ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

async function pull(state) {
  const acct = await api(state, 'GET', '/api/v2/account');
  state.kdf = acct.kdf;
  state.wrapped_key = acct.wrapped_key;
  const { revision, items: changes } = await api(state, 'GET', `/api/v2/sync?since=${state.revision || 0}`);
  // since=0 is a full snapshot without tombstones: replace, or deletions made elsewhere would never arrive.
  if (!state.revision || !state.items) state.items = {};
  for (const it of changes) {
    if (it.deleted) delete state.items[it.id];
    else state.items[it.id] = { id: it.id, data: it.data, revision: it.revision };
  }
  state.revision = revision;
}

async function sync() {
  const state = await getState();
  if (!state) return;
  try {
    await pull(state);
  } catch (e) {
    if (e.status === 401) {
      await setState({ ...state, token: '', expired: true });
      await lock();
    }
    throw e;
  }
  await setState(state);
  cache = null;
  // The master password may have changed elsewhere; the current vault key stays valid (it is never rotated).
}

function deviceName() {
  const ua = navigator.userAgent;
  const browser = ua.includes('Firefox') ? 'Firefox' : ua.includes('Edg/') ? 'Edge' : 'Chrome';
  return `storii for ${browser}`;
}

async function login({ server, username, password, register }) {
  server = server.trim().replace(/\/+$/, '');
  if (!/^https?:\/\//.test(server)) server = 'https://' + server;
  const base = { server, token: '' };
  const ping = await api(base, 'GET', '/api/v2/ping');
  if (ping.api !== 'v2') throw new Error('that is not a storii v2 server');
  let resp, vaultKey;
  if (register) {
    const kdf = newKdf();
    const keys = await deriveKeys(password, kdf);
    vaultKey = randomBytes(32);
    resp = await api(base, 'POST', '/api/v2/register', {
      username, kdf, auth_key: toB64(keys.auth), wrapped_key: await wrapVaultKey(keys.wrap, vaultKey), device_name: deviceName(),
    });
  } else {
    const { kdf } = await api(base, 'POST', '/api/v2/prelogin', { username });
    const keys = await deriveKeys(password, kdf);
    resp = await api(base, 'POST', '/api/v2/login', { username, auth_key: toB64(keys.auth), device_name: deviceName() });
    vaultKey = await unwrapVaultKey(keys.wrap, resp.account.wrapped_key);
  }
  const state = { server, username: resp.account.username, token: resp.token, kdf: resp.account.kdf,
    wrapped_key: resp.account.wrapped_key, revision: 0, items: {} };
  await pull(state);
  await setState(state);
  await chrome.storage.session.set({ vaultKey: toB64(vaultKey) });
  cache = null;
  await touch();
  updateBadge();
}

async function unlock({ password }) {
  const state = await getState();
  if (!state) throw new Error('not set up');
  const keys = await deriveKeys(password, state.kdf);
  let vaultKey;
  try {
    vaultKey = await unwrapVaultKey(keys.wrap, state.wrapped_key);
  } catch {
    throw new Error('wrong master password');
  }
  await chrome.storage.session.set({ vaultKey: toB64(vaultKey) });
  cache = null;
  await touch();
  updateBadge();
  sync().catch(() => {});
}

async function logout() {
  const state = await getState();
  if (state?.token) await api(state, 'POST', '/api/v2/logout').catch(() => {});
  await lock();
  await chrome.storage.local.remove('state');
}

// Writes go to the server first, then into the local copy.
async function write(changes) {
  const key = await getVaultKey();
  const state = await getState();
  if (!key || !state) throw new Error('locked');
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const writes = [];
  const plain = {};
  for (const ch of changes) {
    if (ch.delete) {
      writes.push({ id: ch.id, delete: true });
      continue;
    }
    const id = ch.id || crypto.randomUUID();
    const item = { ...ch.item, created_at: ch.item.created_at || now, updated_at: now };
    plain[id] = item;
    writes.push({ id, data: await encryptItem(key, id, item) });
  }
  const { revision } = await api(state, 'POST', '/api/v2/items', { writes });
  for (const w of writes) {
    if (w.delete) delete state.items[w.id];
    else state.items[w.id] = { id: w.id, data: w.data, revision };
  }
  await setState(state);
  cache = null;
  await touch();
  return writes.map((w) => w.id);
}

async function deleteItems(ids) {
  const all = await items();
  const changes = [];
  // Deleting a context unlinks it from its secrets.
  for (const [sid, s] of all) {
    if (ids.includes(sid) || !s.contexts?.some((c) => ids.includes(c))) continue;
    changes.push({ id: sid, item: { ...s, contexts: s.contexts.filter((c) => !ids.includes(c)) } });
  }
  for (const id of ids) changes.push({ id, delete: true });
  return write(changes);
}

// Site matching for content scripts.

async function secretsForHost(host) {
  const all = await items();
  if (!all || !host) return [];
  const ctxIds = new Set([...all].filter(([, it]) => contextMatches(it, host)).map(([id]) => id));
  return [...all].filter(([, it]) => it.kind === 'secret' && it.contexts?.some((c) => ctxIds.has(c)))
    .map(([id, it]) => ({ id, ...it }));
}

function senderHost(sender) {
  return hostOf(sender.url || sender.origin || '');
}

function isExtensionPage(sender) {
  return sender.id === chrome.runtime.id && (sender.url || '').startsWith(chrome.runtime.getURL(''));
}

// Logins submitted in a tab that aren't in the vault yet, offered for saving on the next page.
// Kept in storage.session (memory only) because the worker can be stopped between two page loads.
const pendingSaves = {
  async all() {
    return (await chrome.storage.session.get('pending')).pending || {};
  },
  async get(tabId) {
    return (await this.all())[tabId] || null;
  },
  async set(tabId, value) {
    const all = await this.all();
    all[tabId] = value;
    await chrome.storage.session.set({ pending: all });
  },
  async delete(tabId) {
    const all = await this.all();
    delete all[tabId];
    await chrome.storage.session.set({ pending: all });
  },
};

async function noteSubmission(sender, { username, password }) {
  const host = senderHost(sender);
  if (!host || !password || !sender.tab) return;
  const all = await items();
  let existingId = null;
  if (all) {
    for (const s of await secretsForHost(host)) {
      if (s.type !== 'password') continue;
      if (s.fields?.password === password && (!username || s.fields?.username === username)) return; // known
      if (username && s.fields?.username === username) existingId = s.id;
      // A login without a username (e.g. migrated from v1) used with this password: add the username to it.
      else if (username && !existingId && !s.fields?.username && s.fields?.password === password) existingId = s.id;
    }
  }
  await pendingSaves.set(sender.tab.id, { host, username, password, existingId, at: Date.now() });
}

async function pendingFor(tabId) {
  const p = await pendingSaves.get(tabId);
  if (p && Date.now() - p.at > 5 * 60 * 1000) {
    await pendingSaves.delete(tabId);
    return null;
  }
  return p || null;
}

async function savePending(tabId) {
  const p = await pendingFor(tabId);
  if (!p) return null;
  await pendingSaves.delete(tabId);
  const all = await items();
  if (!all) throw new Error('locked');
  if (p.existingId) {
    const s = all.get(p.existingId);
    const fields = { ...s.fields, password: p.password };
    if (p.username) fields.username = p.username;
    await write([{ id: p.existingId, item: { ...s, fields } }]);
    return p.existingId;
  }
  let ctxId = [...all].find(([, it]) => it.kind === 'context' && (it.urls || []).some((u) => hostOf(u) === p.host))?.[0];
  const changes = [];
  if (!ctxId) {
    ctxId = crypto.randomUUID();
    changes.push({ id: ctxId, item: { kind: 'context', name: p.host, context_type: 'website', urls: [`https://${p.host}`] } });
  }
  const id = crypto.randomUUID();
  changes.push({ id, item: { kind: 'secret', type: 'password', name: p.host, contexts: [ctxId],
    fields: { username: p.username || '', password: p.password } } });
  await write(changes);
  return id;
}

async function openUnlock() {
  try {
    await chrome.action.openPopup();
  } catch {
    await chrome.windows.create({ url: chrome.runtime.getURL('popup/popup.html?window=1'), type: 'popup', width: 380, height: 600 });
  }
}

// Messages.

const handlers = {
  // Anyone (popup or content script).
  async status() {
    const state = await getState();
    return { configured: !!state, expired: !!state?.expired, unlocked: !!(await getVaultKey()),
      username: state?.username, server: state?.server };
  },
  async openUnlock() {
    await openUnlock();
  },

  // Content scripts: only what matches their own frame.
  async matches(_msg, sender) {
    if (!(await getVaultKey())) return { locked: true, items: [] };
    const found = await secretsForHost(senderHost(sender));
    return { locked: false, items: found.filter((s) => s.type === 'password' || s.type === 'totp')
      .map((s) => ({ id: s.id, name: s.name, type: s.type, username: s.fields?.username || s.fields?.account || '' })) };
  },
  async credential({ id }, sender) {
    const s = (await secretsForHost(senderHost(sender))).find((x) => x.id === id);
    if (!s) throw new Error('that secret does not belong to this site');
    await touch();
    if (s.type === 'totp') return { code: await totpCode(totpFromFields(s.fields)) };
    return { username: s.fields?.username || '', password: s.fields?.password || '' };
  },
  async submitted(msg, sender) {
    await noteSubmission(sender, msg);
  },
  async pendingSave(_msg, sender) {
    if (!sender.tab || !(await getVaultKey())) return null;
    const p = await pendingFor(sender.tab.id);
    return p && p.host === senderHost(sender) ? { host: p.host, username: p.username, update: !!p.existingId } : null;
  },
  async confirmSave({ save }, sender) {
    if (!save) return void (await pendingSaves.delete(sender.tab.id));
    return savePending(sender.tab.id);
  },
};

const popupHandlers = {
  login,
  unlock,
  lock,
  logout,
  sync,
  async items() {
    const all = await items();
    if (!all) throw new Error('locked');
    await touch();
    return [...all].map(([id, it]) => ({ id, ...it }));
  },
  async save({ id, item }) {
    return (await write([{ id, item }]))[0];
  },
  async saveMany({ changes }) {
    return write(changes);
  },
  async delete({ ids }) {
    return deleteItems(ids);
  },
  async settings({ set }) {
    if (set) {
      await chrome.storage.local.set({ settings: { ...(await getSettings()), ...set } });
      await touch();
    }
    return getSettings();
  },
  async pendingForTab({ tabId }) {
    return pendingFor(tabId);
  },
  async savePendingForTab({ tabId, discard }) {
    if (discard) return void (await pendingSaves.delete(tabId));
    return savePending(tabId);
  },
  // Fill a secret the user picked in the popup into the active tab.
  async fillTab({ tabId, id }) {
    const s = (await items())?.get(id);
    if (!s) throw new Error('locked');
    const payload = s.type === 'totp' ? { code: await totpCode(totpFromFields(s.fields)) }
      : { username: s.fields?.username || '', password: s.fields?.password || '' };
    await chrome.tabs.sendMessage(tabId, { type: 'fill', ...payload });
  },
};

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const fromPopup = isExtensionPage(sender);
  const fn = handlers[msg.type] || (fromPopup && popupHandlers[msg.type]);
  if (!fn) {
    reply({ error: 'unknown request' });
    return false;
  }
  Promise.resolve(fn(msg, sender)).then((result) => reply({ result }), (e) => reply({ error: e.message || String(e) }));
  return true;
});

chrome.commands?.onCommand.addListener(async (command, tab) => {
  if (command !== 'fill-login') return;
  tab ||= (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (!tab) return;
  if (!(await getVaultKey())) return openUnlock();
  chrome.tabs.sendMessage(tab.id, { type: 'fillShortcut' }).catch(() => {});
});

chrome.runtime.onStartup?.addListener(updateBadge);
chrome.runtime.onInstalled.addListener(updateBadge);
chrome.tabs.onRemoved.addListener((tabId) => pendingSaves.delete(tabId));
