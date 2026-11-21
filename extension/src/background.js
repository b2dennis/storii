// The background worker owns the vault: the encrypted copy in storage.local, and while unlocked the vault key in
// storage.session (memory only, gone when the browser closes). Content scripts only ever get the secrets of
// contexts that match the frame they run in.
import { sealBackup, openBackup, restorePlan } from './lib/backup.js';
import { deriveKeys, newKdf, randomBytes, toB64, fromB64, wrapVaultKey, unwrapVaultKey, encryptItem, decryptItem, seal, open } from './lib/crypto.js';
import { contextMatches, host as hostOf } from './lib/match.js';
import { totpFromFields, totpCode } from './lib/totp.js';
import { cardBrand, cardDigits, cardValid, normalizeExpiry } from './lib/card.js';
import { createPasskey, assertPasskey, rpIdAllowed } from './lib/passkey.js';
import { withHistory } from './lib/history.js';
import * as share from './lib/share.js';

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

// Decrypted items, cached per worker lifetime and rebuilt on demand. Items kept in a share are in the same map;
// itemShare says which share (docs/CRYPTO.md#sharing).
let cache = null; // Map id -> item
let itemShare = new Map(); // item id -> share id
let shareInfo = new Map(); // share id -> { id, name, owner, members, mine, key }
let sharePriv = null;

async function items() {
  if (cache) return cache;
  const key = await getVaultKey();
  const state = await getState();
  if (!key || !state) return null;
  const all = new Map();
  for (const [id, it] of Object.entries(state.items || {})) {
    try {
      all.set(id, await decryptItem(key, id, it.data));
    } catch {
      console.warn('storii: could not decrypt item', id);
    }
  }
  const where = new Map();
  const info = new Map();
  let priv = null;
  if (state.sealed_private_key) {
    try {
      priv = await share.openSharePrivateKey(key, state.sealed_private_key);
    } catch { /* not ours */ }
  }
  for (const sh of priv ? Object.values(state.shares || {}) : []) {
    let sk;
    try {
      sk = await share.unwrapShareKey(priv, sh.id, sh.wrapped_key);
    } catch {
      continue;
    }
    const meta = await share.openShareMeta(sk, sh.id, sh.meta).catch(() => ({ name: '' }));
    info.set(sh.id, { id: sh.id, name: meta.name, owner: sh.owner, members: sh.members || [],
      mine: sh.owner.toLowerCase() === state.username.toLowerCase(), key: sk });
    for (const [id, it] of Object.entries(sh.items || {})) {
      if (all.has(id)) continue; // the personal copy wins
      try {
        all.set(id, await share.decryptShareItem(sk, sh.id, id, it.data));
        where.set(id, sh.id);
      } catch {
        console.warn('storii: could not decrypt shared item', id);
      }
    }
  }
  [cache, itemShare, shareInfo, sharePriv] = [all, where, info, priv];
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
  state.public_key = acct.public_key || '';
  state.sealed_private_key = acct.sealed_private_key || '';
  await pullShares(state);
  const { revision, items: changes } = await api(state, 'GET', `/api/v2/sync?since=${state.revision || 0}`);
  // since=0 is a full snapshot without tombstones: replace, or deletions made elsewhere would never arrive.
  if (!state.revision || !state.items) state.items = {};
  for (const it of changes) {
    if (it.deleted) delete state.items[it.id];
    else state.items[it.id] = { id: it.id, data: it.data, revision: it.revision };
  }
  state.revision = revision;
}

// Follows the shares list: new shares are fetched whole, changed ones from their revision, gone ones dropped.
async function pullShares(state) {
  let list;
  try {
    ({ shares: list } = await api(state, 'GET', '/api/v2/shares'));
  } catch (e) {
    if (e.status === 404) return; // a server from before sharing
    throw e;
  }
  const old = state.shares || {};
  const next = {};
  for (const r of list) {
    let sh = old[r.id];
    if (!sh || sh.wrapped_key !== r.wrapped_key) sh = { id: r.id, revision: 0, items: {} };
    Object.assign(sh, { owner: r.owner, meta: r.meta, wrapped_key: r.wrapped_key, members: r.members });
    if (r.revision !== sh.revision) {
      const { revision, items: changes } = await api(state, 'GET', `/api/v2/shares/${r.id}/sync?since=${sh.revision}`);
      if (!sh.revision) sh.items = {};
      for (const it of changes) {
        if (it.deleted) delete sh.items[it.id];
        else sh.items[it.id] = { id: it.id, data: it.data, revision: it.revision };
      }
      sh.revision = revision;
    }
    next[r.id] = sh;
  }
  state.shares = next;
}

// Every account gets a sharing key pair, so others can add it to shares. The first device to ask wins.
async function setupSharing() {
  const key = await getVaultKey();
  const state = await getState();
  if (!key || !state || state.public_key) return;
  const { priv, pub } = await share.newShareKeyPair();
  let acct;
  try {
    acct = await api(state, 'PUT', '/api/v2/account/keys',
      { public_key: toB64(pub), sealed_private_key: await share.sealSharePrivateKey(key, priv) });
  } catch (e) {
    if (e.status === 404) return;
    if (e.status !== 409) throw e;
    acct = await api(state, 'GET', '/api/v2/account');
  }
  state.public_key = acct.public_key;
  state.sealed_private_key = acct.sealed_private_key;
  await setState(state);
  cache = null;
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
  if (!state.public_key && (await getVaultKey())) await setupSharing().catch(() => {});
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
  await setupSharing().catch(() => {});
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

// Quick unlock: a passkey for this extension (Windows Hello, Touch ID, a phone or a security key) whose WebAuthn PRF
// output wraps the vault key. The popup runs the ceremony and hands over the 32-byte PRF output; the wrapped key
// stays in this browser's storage and is useless without the authenticator.
async function quickKey(prf) {
  const raw = fromB64(prf);
  if (raw.length !== 32) throw new Error('bad PRF output');
  const k = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('storii:quick-unlock') }, k, 256));
}

async function quickUnlockSetup({ prf, credentialId, salt, rpId }) {
  const vaultKey = await getVaultKey();
  if (!vaultKey) throw new Error('locked');
  const state = await getState();
  const wrapped = await seal(await quickKey(prf), vaultKey, 'storii:quick-unlock');
  // rpId: Firefox's passkey belongs to the server's host (see popup.js); Chrome's to the extension itself.
  await chrome.storage.local.set({ quickUnlock: { credentialId, salt, wrapped, rpId, account: `${state.username}@${state.server}` } });
}

async function quickUnlock({ prf }) {
  const { quickUnlock: q } = await chrome.storage.local.get('quickUnlock');
  if (!q) throw new Error('quick unlock is off');
  let vaultKey;
  try {
    vaultKey = await open(await quickKey(prf), q.wrapped, 'storii:quick-unlock');
  } catch {
    throw new Error('That passkey does not unlock this vault. Unlock with your master password and set it up again.');
  }
  // The key must still open this account's vault (e.g. after logging in as someone else).
  const state = await getState();
  for (const [id, it] of Object.entries(state?.items || {}).slice(0, 1)) await decryptItem(vaultKey, id, it.data);
  await chrome.storage.session.set({ vaultKey: toB64(vaultKey) });
  cache = null;
  await touch();
  updateBadge();
  sync().catch(() => {});
}

async function logout() {
  await chrome.storage.local.remove('quickUnlock');
  const state = await getState();
  if (state?.token) await api(state, 'POST', '/api/v2/logout').catch(() => {});
  await lock();
  await chrome.storage.local.remove('state');
}

// Writes go to the server first, then into the local copy.
const WRITE_CHUNK = 1000;

// Encrypts an item for where it's kept: the personal vault (shareId '') or a share.
async function encryptFor(shareId, id, item) {
  if (!shareId) return encryptItem(await getVaultKey(), id, item);
  const sh = shareInfo.get(shareId);
  if (!sh) throw new Error('no such share');
  return share.encryptShareItem(sh.key, shareId, id, item);
}

// Sends writes to the place each one names ({ id, data | delete, place }), chunked, keeping each stored chunk.
async function send(state, writes) {
  const groups = new Map();
  for (const w of writes) groups.set(w.place || '', [...(groups.get(w.place || '') || []), w]);
  for (const [place, ws] of groups) {
    // The server takes at most 2000 writes per request (a big import has more).
    for (let i = 0; i < ws.length; i += WRITE_CHUNK) {
      const chunk = ws.slice(i, i + WRITE_CHUNK).map(({ place: _, ...w }) => w);
      const path = place ? `/api/v2/shares/${place}/items` : '/api/v2/items';
      const { revision } = await api(state, 'POST', path, { writes: chunk });
      const store = place ? state.shares[place].items : state.items;
      for (const w of chunk) {
        if (w.delete) delete store[w.id];
        else store[w.id] = { id: w.id, data: w.data, revision };
      }
      await setState(state);
    }
  }
  cache = null;
}

// changes: [{ id?, item, share? } | { id, delete: true }]. Existing items stay where they are; new ones go into
// `share` (a share id) or the personal vault.
async function write(changes) {
  const key = await getVaultKey();
  const state = await getState();
  if (!key || !state) throw new Error('locked');
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const writes = [];
  const known = await items();
  for (const ch of changes) {
    const existing = ch.id && known?.has(ch.id);
    if (ch.delete) {
      writes.push({ id: ch.id, delete: true, place: itemShare.get(ch.id) || '' });
      continue;
    }
    const id = ch.id || crypto.randomUUID();
    const place = existing ? itemShare.get(id) || '' : ch.share || '';
    const prev = ch.id && known?.get(ch.id);
    let item = { ...ch.item, created_at: ch.item.created_at || now, updated_at: now };
    if (prev) item = withHistory(prev, item, now);
    writes.push({ id, data: await encryptFor(place, id, item), place });
  }
  await send(state, writes);
  await touch();
  return writes.map((w) => w.id);
}

// Moves items into a share (or home with shareId ''), under the same ids. A moved secret's contexts go along when
// nothing staying behind uses them; otherwise it gets a copy of the context in its new place.
async function moveItems(ids, shareId) {
  const state = await getState();
  const all = await items();
  if (!all || !state) throw new Error('locked');
  if (shareId && !shareInfo.has(shareId)) throw new Error('no such share');
  const placeOf = (id) => itemShare.get(id) || '';
  const moving = new Set(ids.filter((id) => all.has(id) && placeOf(id) !== shareId));
  const out = new Map([...moving].map((id) => [id, all.get(id)]));
  for (const id of [...moving]) {
    const it = out.get(id);
    if (it.kind !== 'secret') continue;
    const contexts = [...(it.contexts || [])];
    contexts.forEach((c, i) => {
      if (moving.has(c) || placeOf(c) === shareId || !all.has(c)) return;
      const usedElsewhere = [...all].some(([sid, s]) => !moving.has(sid) && s.contexts?.includes(c));
      if (!usedElsewhere) {
        moving.add(c);
        out.set(c, all.get(c));
        return;
      }
      const copy = crypto.randomUUID();
      const { created_at: _, ...ctx } = all.get(c);
      out.set(copy, ctx);
      moving.add(copy);
      contexts[i] = copy;
    });
    out.set(id, { ...it, contexts });
  }
  if (!out.size) return 0;
  const now = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  const puts = [];
  const deletes = [];
  for (const [id, it] of out) {
    const item = { ...it, created_at: it.created_at || now };
    puts.push({ id, data: await encryptFor(shareId, id, item), place: shareId });
    if (all.has(id)) deletes.push({ id, delete: true, place: placeOf(id) });
  }
  // The new place first, so a failure halfway leaves a copy rather than nothing.
  await send(state, puts);
  await send(state, deletes);
  // A moved item isn't deleted: keep it out of the personal trash, where restoring it would duplicate it.
  const home = deletes.filter((d) => !d.place).map((d) => d.id);
  if (home.length) await api(state, 'DELETE', '/api/v2/trash', { ids: home }).catch(() => {});
  await touch();
  return out.size;
}

async function sharesList() {
  await items();
  const state = await getState();
  const count = new Map();
  for (const sid of itemShare.values()) count.set(sid, (count.get(sid) || 0) + 1);
  const pub = state?.public_key ? fromB64(state.public_key) : null;
  return {
    fingerprint: pub ? await share.fingerprint(pub) : '',
    username: state?.username,
    shares: [...shareInfo.values()].map(({ key: _, ...s }) => ({ ...s, items: count.get(s.id) || 0 }))
      .sort((a, b) => a.name.localeCompare(b.name)),
  };
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

// The popup and storii's own windows, and the unlock frame inside the page picker (Chrome serves that one from a
// per-session dynamic id, so the URL can't be compared with getURL; no other extension's pages carry our id).
function isExtensionPage(sender) {
  return sender.id === chrome.runtime.id && (sender.url || '').startsWith(chrome.runtime.getURL('')) ||
    (sender.id === chrome.runtime.id && /^(chrome|moz)-extension:\/\/[^/]+\/unlock\/unlock\.html/.test(sender.url || ''));
}

// Per-tab state kept in storage.session (memory only) because the worker can be stopped between two page loads.
// Every change is a read-modify-write of one storage key, and several frames of a tab send theirs at once: changes
// run one after the other, or one would overwrite another (a card's CVC typed in its own iframe got lost).
function tabStore(key) {
  let queue = Promise.resolve();
  const all = async () => (await chrome.storage.session.get(key))[key] || {};
  return {
    async get(tabId) {
      await queue;
      return (await all())[tabId] || null;
    },
    // fn gets the tab's value (or null) and returns the new one; undefined deletes it.
    update(tabId, fn) {
      const run = queue.then(async () => {
        const m = await all();
        const v = await fn(m[tabId] || null);
        if (v === undefined) {
          if (!(tabId in m)) return v;
          delete m[tabId];
        } else {
          m[tabId] = v;
        }
        await chrome.storage.session.set({ [key]: m });
        return v;
      });
      queue = run.catch(() => {});
      return run;
    },
    set(tabId, value) {
      return this.update(tabId, () => value);
    },
    delete(tabId) {
      return this.update(tabId, () => undefined);
    },
  };
}

// Logins and cards submitted in a tab that aren't in the vault yet, offered for saving.
const pendingSaves = tabStore('pending');
// Card fields typed in a tab so far, merged across its frames (payment providers often put the number, expiry and
// CVC each in their own iframe, while the Pay button is on the page itself).
const cardDrafts = tabStore('cardDrafts');

// What saving this login would do: null when the vault has it already, else { existingId } (null: a new login).
// Without the vault (locked) it can't tell; savePending asks again once it's unlocked.
async function loginPlan(host, username, password) {
  const logins = (await secretsForHost(host)).filter((s) => s.type === 'password');
  let existingId = null;
  // A new password without a username (reset and change-password forms) replaces the site's only login.
  if (!username && logins.length === 1) existingId = logins[0].id;
  for (const s of logins) {
    if (s.fields?.password === password && (!username || s.fields?.username === username)) return null; // known
    if (username && s.fields?.username === username) existingId = s.id;
    // A login without a username (e.g. migrated from v1) used with this password: add the username to it.
    else if (username && !existingId && !s.fields?.username && s.fields?.password === password) existingId = s.id;
  }
  return { existingId };
}

async function noteSubmission(sender, { username, password }) {
  const host = senderHost(sender);
  if (!host || !password || !sender.tab) return;
  const checked = !!(await items());
  let existingId = null;
  if (checked) {
    const plan = await loginPlan(host, username, password);
    if (!plan) return;
    existingId = plan.existingId;
  }
  await pendingSaves.set(sender.tab.id, { host, username, password, existingId, checked, at: Date.now() });
}

// The last two labels of a host (three under short second-level domains like co.uk): close enough to a registrable
// domain for deciding whether a redirect stayed on the same site.
function siteOf(h) {
  const l = (h || '').split('.');
  if (l.length <= 2 || /^[\d.]+$/.test(h)) return h;
  const n = l.at(-2).length <= 3 && l.at(-1).length === 2 ? 3 : 2;
  return l.slice(-n).join('.');
}

async function pendingFor(tabId) {
  const p = await pendingSaves.get(tabId);
  if (p && Date.now() - p.at > 5 * 60 * 1000) {
    await pendingSaves.delete(tabId);
    return null;
  }
  return p || null;
}

const haveCard = (all, number) => [...all.values()].some((it) => it.type === 'card' && cardDigits(it.fields?.number) === number);

// Adds what a frame has of a card (number, name, month, year, exp, cvc) to the tab's draft.
function mergeCardDraft(tabId, part) {
  return cardDrafts.update(tabId, (d) => {
    d ||= {};
    for (const k of ['number', 'name', 'month', 'year', 'exp', 'cvc']) {
      const v = String(part?.[k] ?? '').trim();
      if (v) d[k] = v;
    }
    d.at = Date.now();
    return d;
  });
}

// The tab's card draft becomes a pending save if it holds a card storii doesn't have yet. Returns whether it did.
async function commitCard(tab) {
  let d = null;
  await cardDrafts.update(tab.id, (draft) => {
    if (!draft) return undefined;
    const stale = Date.now() - draft.at > 10 * 60 * 1000;
    // Not a whole card yet (e.g. "Next" before the payment step): keep it for later.
    if (!stale && !cardValid(draft.number)) return draft;
    if (!stale) d = draft;
    return undefined; // taken, or too old
  });
  if (!d) return false;
  const number = cardDigits(d.number);
  const all = await items();
  if (all && haveCard(all, number)) return false;
  const expiry = normalizeExpiry(d.exp || (d.month && d.year ? `${d.month}/${String(d.year).slice(-2)}` : ''));
  await pendingSaves.set(tab.id, { kind: 'card', host: hostOf(tab.url || ''), at: Date.now(), checked: !!all,
    card: { number, cardholder: d.name || '', expiry, cvc: d.cvc || '' } });
  return true;
}

async function savePending(tabId) {
  const p = await pendingFor(tabId);
  if (!p) return null;
  await pendingSaves.delete(tabId);
  const all = await items();
  if (!all) throw new Error('locked');
  if (p.kind === 'card') {
    if (haveCard(all, p.card.number)) return null; // noted while locked, and it was there after all
    const brand = cardBrand(p.card.number);
    const fields = Object.fromEntries(Object.entries(p.card).filter(([, v]) => v));
    const name = `${brand ? brand[0].toUpperCase() + brand.slice(1) : 'Card'} ${p.card.number.slice(-4)}`;
    return (await write([{ id: undefined, item: { kind: 'secret', type: 'card', name, fields } }]))[0];
  }
  if (!p.checked) {
    const plan = await loginPlan(p.host, p.username, p.password);
    if (!plan) return null;
    p.existingId = plan.existingId;
  }
  const s = p.existingId && all.get(p.existingId);
  if (s) {
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

// Passkeys: every request is approved in a small storii window (which also unlocks the vault when needed).
const passkeyReqs = new Map(); // reqId -> { req, resolve, windowId }

function askPasskey(req) {
  return new Promise((resolve) => {
    const reqId = crypto.randomUUID();
    const entry = { req, resolve, windowId: null };
    passkeyReqs.set(reqId, entry);
    chrome.windows.create({ url: chrome.runtime.getURL(`popup/popup.html?window=1&passkey=${reqId}`), type: 'popup', width: 380, height: 560 })
      .then((w) => (entry.windowId = w.id), () => { passkeyReqs.delete(reqId); resolve({ action: 'cancel' }); });
  });
}

chrome.windows.onRemoved.addListener((windowId) => {
  for (const [id, p] of passkeyReqs) {
    if (p.windowId !== windowId) continue;
    passkeyReqs.delete(id);
    p.resolve({ action: 'cancel' });
  }
});

function passkeysFor(all, rpId, ids = []) {
  return [...all].filter(([, it]) => it.kind === 'secret' && it.type === 'passkey' && it.fields?.rp_id === rpId &&
    (!ids.length || ids.includes(it.fields.credential_id)));
}

const NOT_ALLOWED = { error: 'NotAllowedError', message: 'The operation either timed out or was not allowed.' };

async function passkey({ op, data }, sender) {
  // The origin comes from the browser, never from the page.
  let origin = sender.origin && sender.origin !== 'null' ? sender.origin : '';
  try {
    origin ||= new URL(sender.url).origin;
  } catch {
    return { fallback: true };
  }
  if (!sender.tab || !data || typeof data.challenge !== 'string' || !rpIdAllowed(data.rpId, origin) || !(await getState())) return { fallback: true };
  let crossOrigin = false;
  try {
    crossOrigin = sender.frameId !== 0 && new URL(sender.tab.url).origin !== origin;
  } catch {}
  const known = await items();
  if (known && op === 'get' && !passkeysFor(known, data.rpId, data.allow).length) return { fallback: true };
  if (known && op === 'create' && data.exclude?.length && passkeysFor(known, data.rpId, data.exclude).length) {
    return { error: 'InvalidStateError', message: 'storii already has a passkey for this account.' };
  }
  const d = await askPasskey({ op, rpId: data.rpId, rpName: data.rpName, user: data.user, allow: data.allow || [] });
  if (d.action === 'fallback') return { fallback: true };
  const all = await items();
  if (!all || (d.action !== 'save' && d.action !== 'use')) return NOT_ALLOWED;
  await touch();
  if (op === 'create') {
    const { passkey: pk, response } = await createPasskey({ rpId: data.rpId, origin, challenge: data.challenge, user: data.user, crossOrigin });
    const changes = [];
    let ctxId = [...all].find(([, it]) => contextMatches(it, data.rpId))?.[0];
    if (!ctxId) {
      ctxId = crypto.randomUUID();
      changes.push({ id: ctxId, item: { kind: 'context', name: data.rpId, context_type: 'website', urls: [`https://${data.rpId}`] } });
    }
    changes.push({ id: undefined, item: { kind: 'secret', type: 'passkey', name: data.rpName || data.rpId, contexts: [ctxId], fields: pk } });
    await write(changes);
    return { credential: response };
  }
  const it = all.get(d.id);
  if (!it || it.type !== 'passkey' || it.fields?.rp_id !== data.rpId) return NOT_ALLOWED;
  return { credential: await assertPasskey({ passkey: it.fields, origin, challenge: data.challenge, crossOrigin }) };
}

// Messages.

const handlers = {
  passkey,
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
  // Cards aren't tied to a site: any checkout may list them (name and last digits only).
  async cards() {
    const all = await items();
    if (!all) return { locked: true, items: [] };
    return { locked: false, items: [...all].filter(([, it]) => it.kind === 'secret' && it.type === 'card')
      .map(([id, it]) => ({ id, name: it.name, last4: cardDigits(it.fields?.number).slice(-4), brand: cardBrand(it.fields?.number) })) };
  },
  // Fills a card the user picked into the tab's frames that may take it: the page's own site and payment providers'
  // frames (card fields often sit in Stripe-style iframes, one per field). Each frame checks that itself.
  async fillCard({ id }, sender) {
    const it = (await items())?.get(id);
    if (!it || it.type !== 'card' || !sender.tab) throw new Error('no such card');
    await touch();
    const f = it.fields || {};
    await chrome.tabs.sendMessage(sender.tab.id, { type: 'fillCard', topHost: hostOf(sender.tab.url || ''),
      card: { cardholder: f.cardholder || '', number: cardDigits(f.number), expiry: f.expiry || '', cvc: f.cvc || '' } });
  },
  async credential({ id }, sender) {
    const s = (await secretsForHost(senderHost(sender))).find((x) => x.id === id);
    if (!s) throw new Error('that secret does not belong to this site');
    await touch();
    if (s.type === 'totp') return { code: await totpCode(totpFromFields(s.fields)) };
    return { username: s.fields?.username || '', password: s.fields?.password || '' };
  },
  // A card field changed in some frame of the tab.
  async cardDraft({ card }, sender) {
    if (sender.tab) await mergeCardDraft(sender.tab.id, card);
  },
  // Something in the tab was submitted or a pay/save button clicked: offer the card typed so far, right away (many
  // checkouts never load a new page) and again on the next page if it does.
  async cardSubmitted({ card }, sender) {
    if (!sender.tab) return;
    await mergeCardDraft(sender.tab.id, card);
    // The other frames' last change events may still be on their way.
    await new Promise((r) => setTimeout(r, 300));
    if (await commitCard(sender.tab)) chrome.tabs.sendMessage(sender.tab.id, { type: 'showSave' }, { frameId: 0 }).catch(() => {});
  },
  async submitted(msg, sender) {
    await noteSubmission(sender, msg);
  },
  async pendingSave(_msg, sender) {
    if (!sender.tab) return null;
    // A card typed on the previous page, which then went on without a click storii recognised.
    if (!(await pendingSaves.get(sender.tab.id))) await commitCard(sender.tab);
    const p = await pendingFor(sender.tab.id);
    if (!p) return null;
    const locked = !(await getVaultKey());
    // Pages often redirect right after a login, also to another host (login.example.com → app.example.com, SSO):
    // offer it on the page the tab ends up on. Same site for 5 minutes, any site for the first minute.
    const here = senderHost(sender);
    if (here !== p.host && siteOf(here) !== siteOf(p.host) && Date.now() - p.at > 60 * 1000) return null;
    if (p.kind === 'card') return { host: p.host, locked, card: { brand: cardBrand(p.card.number), last4: p.card.number.slice(-4) } };
    return { host: p.host, locked, username: p.username, update: !!p.existingId };
  },
  async confirmSave({ save }, sender) {
    if (!save) return void (await pendingSaves.delete(sender.tab.id));
    return savePending(sender.tab.id);
  },
};

const popupHandlers = {
  async passkeyRequest({ reqId }) {
    const p = passkeyReqs.get(reqId);
    if (!p) return null;
    const all = await items();
    const passkeys = p.req.op === 'get' && all ? passkeysFor(all, p.req.rpId, p.req.allow)
      .map(([id, it]) => ({ id, name: it.name, user: it.fields.user_name || it.fields.user_display_name || '' })) : [];
    return { ...p.req, passkeys };
  },
  async passkeyDecision({ reqId, action, id }) {
    const p = passkeyReqs.get(reqId);
    if (!p) return;
    passkeyReqs.delete(reqId);
    p.resolve({ action, id });
  },
  login,
  unlock,
  quickUnlock,
  quickUnlockSetup,
  async quickUnlockInfo() {
    const { quickUnlock: q } = await chrome.storage.local.get('quickUnlock');
    return q ? { credentialId: q.credentialId, salt: q.salt, rpId: q.rpId } : null;
  },
  async quickUnlockOff() {
    await chrome.storage.local.remove('quickUnlock');
  },
  lock,
  logout,
  sync,
  async items() {
    const all = await items();
    if (!all) throw new Error('locked');
    await touch();
    return [...all].map(([id, it]) => ({ id, ...it, ...(itemShare.has(id) ? { share: itemShare.get(id) } : {}) }));
  },
  // Sharing.
  async shares() {
    if (!(await items())) throw new Error('locked');
    await setupSharing().catch(() => {});
    await touch();
    return sharesList();
  },
  async createShare({ name }) {
    await setupSharing();
    await items();
    const state = await getState();
    if (!sharePriv) throw new Error('sharing is not set up on this server');
    name = (name || '').trim();
    if (!name) throw new Error('a share needs a name');
    const id = crypto.randomUUID();
    const sk = share.newShareKey();
    const wrapped = await share.wrapShareKey(fromB64(state.public_key), id, sk);
    const meta = await share.sealShareMeta(sk, id, { name });
    await api(state, 'POST', '/api/v2/shares', { id, meta, wrapped_key: wrapped });
    await sync();
    return id;
  },
  async renameShare({ id, name }) {
    await items();
    const sh = shareInfo.get(id);
    if (!sh) throw new Error('no such share');
    await api(await getState(), 'PUT', `/api/v2/shares/${id}`, { meta: await share.sealShareMeta(sh.key, id, { name: name.trim() }) });
    await sync();
  },
  // Someone's public key and fingerprint, to compare with them before adding them.
  async memberKey({ username }) {
    const r = await api(await getState(), 'GET', `/api/v2/users/${encodeURIComponent(username.trim())}/key`);
    const pub = fromB64(r.public_key);
    if (pub.length !== 32) throw new Error('the server sent a malformed key');
    return { username: r.username, public_key: r.public_key, fingerprint: await share.fingerprint(pub) };
  },
  async addMember({ id, username, publicKey }) {
    await items();
    const sh = shareInfo.get(id);
    if (!sh) throw new Error('no such share');
    const wrapped = await share.wrapShareKey(fromB64(publicKey), id, sh.key);
    await api(await getState(), 'PUT', `/api/v2/shares/${id}/members/${encodeURIComponent(username)}`, { wrapped_key: wrapped });
    await sync();
  },
  async removeMember({ id, username }) {
    await api(await getState(), 'DELETE', `/api/v2/shares/${id}/members/${encodeURIComponent(username)}`);
    await sync();
  },
  // Deletes the share and its items (owner) or leaves it (members).
  async deleteShare({ id }) {
    await api(await getState(), 'DELETE', `/api/v2/shares/${id}`);
    await sync();
  },
  async moveItems({ ids, share: shareId }) {
    return moveItems(ids, shareId || '');
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
  // Deleted items the server keeps for a while, decrypted; ones this vault key can't read are left out.
  async trash() {
    const key = await getVaultKey();
    const state = await getState();
    if (!key || !state) throw new Error('locked');
    const { items: list, days } = await api(state, 'GET', '/api/v2/trash');
    const out = [];
    for (const t of list) {
      try {
        out.push({ ...(await decryptItem(key, t.id, t.data)), id: t.id, deleted_at: t.deleted_at });
      } catch { /* not ours to read */ }
    }
    await touch();
    return { items: out, days };
  },
  // Puts deleted items back exactly as they were: the same ciphertext under the same id.
  async restore({ ids }) {
    const state = await getState();
    if (!(await getVaultKey()) || !state) throw new Error('locked');
    const { items: list } = await api(state, 'GET', '/api/v2/trash');
    const writes = list.filter((t) => ids.includes(t.id)).map((t) => ({ id: t.id, data: t.data }));
    if (!writes.length) return 0;
    const { revision } = await api(state, 'POST', '/api/v2/items', { writes });
    for (const w of writes) state.items[w.id] = { id: w.id, data: w.data, revision };
    await setState(state);
    cache = null;
    await touch();
    return writes.length;
  },
  // An encrypted backup of every item (the file's text), sealed with a backup password.
  async backup({ password }) {
    const all = await items();
    if (!all) throw new Error('locked');
    await touch();
    return sealBackup(password, Object.fromEntries(all));
  },
  // Adds a backup's items that the vault doesn't have, as they were and under their ids; others are left alone.
  async restoreBackup({ password, text, dryRun }) {
    const key = await getVaultKey();
    const state = await getState();
    if (!key || !state) throw new Error('locked');
    const { add, skipped } = restorePlan(await openBackup(password, text), new Set((await items()).keys()));
    if (!dryRun) {
      const writes = [];
      for (const [id, it] of add) writes.push({ id, data: await encryptItem(key, id, it) });
      for (let i = 0; i < writes.length; i += WRITE_CHUNK) {
        const chunk = writes.slice(i, i + WRITE_CHUNK);
        const { revision } = await api(state, 'POST', '/api/v2/items', { writes: chunk });
        for (const w of chunk) state.items[w.id] = { id: w.id, data: w.data, revision };
        await setState(state);
      }
      cache = null;
    }
    await touch();
    return { added: add.map(([, it]) => it.name), skipped };
  },
  // Forgets deleted items for good: ids, or everything.
  async emptyTrash({ ids }) {
    const state = await getState();
    if (!(await getVaultKey()) || !state) throw new Error('locked');
    await api(state, 'DELETE', '/api/v2/trash', { ids: ids || [] });
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
    const all = await items();
    const s = all?.get(id);
    if (!s) throw new Error('locked');
    const payload = s.type === 'totp' ? { code: await totpCode(totpFromFields(s.fields)) }
      : { username: s.fields?.username || '', password: s.fields?.password || '' };
    // Only frames on the secret's own sites fill it, never a third-party iframe on the page.
    const hosts = (s.contexts || []).flatMap((c) => all.get(c)?.urls || []).map(hostOf).filter(Boolean);
    await chrome.tabs.sendMessage(tabId, { type: 'fill', hosts, ...payload });
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
chrome.tabs.onRemoved.addListener((tabId) => {
  pendingSaves.delete(tabId);
  cardDrafts.delete(tabId);
});
