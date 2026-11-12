// Password exports from browsers and password managers (CSV), as internal/importer/importer.go: Zen and Firefox
// ("Export Logins"), Chrome, Edge, Brave and Google Password Manager ("Export passwords"), Safari and Apple Passwords,
// Bitwarden and 1Password CSVs. Shared cases in testdata/import/cases.json.
import { host } from './match.js';

// Column names per field, as the supported exports spell them (lowercased).
const COLUMNS = {
  name: ['name', 'title'],
  url: ['url', 'login_uri', 'website', 'web site'],
  username: ['username', 'login_username', 'login'],
  password: ['password', 'login_password'],
  note: ['note', 'notes', 'extra'],
};

// RFC 4180 records: quoted fields may hold commas, doubled quotes and line breaks.
export function csvRecords(text) {
  text = text.replace(/^﻿/, '');
  const out = [];
  let rec = [], field = '', quoted = false, i = 0;
  while (i < text.length) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i += 2; continue; }
      if (c === '"') { quoted = false; i++; continue; }
      if (c === '\r' && text[i + 1] === '\n') { field += '\n'; i += 2; continue; } // as Go's encoding/csv
      field += c; i++; continue;
    }
    if (c === '"' && field === '') { quoted = true; i++; continue; }
    if (c === ',') { rec.push(field); field = ''; i++; continue; }
    if (c === '\r' || c === '\n') {
      rec.push(field); field = '';
      out.push(rec); rec = [];
      i += c === '\r' && text[i + 1] === '\n' ? 2 : 1;
      continue;
    }
    field += c; i++;
  }
  if (field !== '' || rec.length) { rec.push(field); out.push(rec); }
  return out.filter((r) => !(r.length === 1 && r[0] === ''));
}

export class NotAnExport extends Error {}

/** The logins in an export; the header row decides which column is which. */
export function parseCsv(text) {
  const [header, ...records] = csvRecords(text);
  if (!header) throw new NotAnExport('That file is empty.');
  const idx = {};
  header.forEach((h, i) => {
    h = h.trim().toLowerCase();
    for (const [field, names] of Object.entries(COLUMNS)) if (!(field in idx) && names.includes(h)) idx[field] = i;
  });
  if (!('password' in idx)) throw new NotAnExport('This doesn’t look like a password export: it has no password column.');
  const get = (rec, f) => (f in idx && idx[f] < rec.length ? rec[idx[f]] : '');
  return records.map((r) => ({
    name: get(r, 'name').trim(), url: get(r, 'url').trim(), username: get(r, 'username').trim(),
    password: get(r, 'password'), note: get(r, 'note').trim(),
  }));
}

function looksLikeDomain(s) {
  if (/[ /@]/.test(s) || !s.includes('.')) return false;
  return /^[a-z]{2,}$/.test(s.slice(s.lastIndexOf('.') + 1));
}

/** Where a row's login is used: a web host or an Android package. */
function rowSite(r) {
  if (/^android:\/\//i.test(r.url)) {
    let rest = r.url.slice('android://'.length);
    rest = rest.slice(rest.lastIndexOf('@') + 1);
    return { host: '', pkg: rest.split('/')[0] };
  }
  const h = host(r.url);
  if (h) return { host: h, pkg: '' };
  if (looksLikeDomain(r.name)) return { host: host(r.name), pkg: '' };
  return { host: '', pkg: '' };
}

const siteName = (s) => s.pkg || s.host;

function contextFor(ctx, s) {
  if (ctx?.kind !== 'context') return false;
  if (s.pkg) return (ctx.android_packages || []).includes(s.pkg);
  return (ctx.urls || []).some((u) => host(u) === s.host);
}

/**
 * Matches rows against the vault (id -> item), as importer.Build: a login already there is skipped, one without a
 * username gets it filled in, the rest are added with a website or app context. Returns the items to write and a line
 * per row ({ action: 'add' | 'username' | 'skip' | 'invalid', id, name, site, differs }).
 */
export function buildImport(existing, rows, newId, now = new Date().toISOString().replace(/\.\d+Z$/, 'Z')) {
  const items = new Map(Object.entries(existing));
  const writes = new Map();
  const lines = [];
  const put = (id, it) => { items.set(id, it); writes.set(id, it); };
  const sorted = () => [...items.keys()].sort();

  for (const r of rows) {
    if (!r.password) { lines.push({ action: 'invalid', name: r.name }); continue; }
    const s = rowSite(r);
    const anySite = !!(s.host || s.pkg);
    const name = r.name || siteName(s);
    const line = { name, site: siteName(s), differs: false };
    let same = '', noUser = '', sameUser = '';
    for (const id of sorted()) {
      const it = items.get(id);
      if (it.kind !== 'secret' || it.type !== 'password') continue;
      if (!anySite) {
        if ((it.name || '').toLowerCase() !== name.toLowerCase() || (it.contexts || []).length) continue;
      } else if (!(it.contexts || []).some((c) => contextFor(items.get(c), s))) continue;
      const u = it.fields?.username || '', pw = it.fields?.password || '';
      if (u === r.username && pw === r.password) same = id;
      else if (!u && pw === r.password && r.username && !noUser) noUser = id;
      else if (u === r.username && !sameUser) sameUser = id;
    }
    if (same) {
      Object.assign(line, { action: 'skip', id: same });
    } else if (noUser) {
      const it = items.get(noUser);
      put(noUser, { ...it, fields: { ...it.fields, username: r.username }, updated_at: now });
      Object.assign(line, { action: 'username', id: noUser });
    } else {
      const secret = { kind: 'secret', type: 'password', name, fields: { password: r.password }, created_at: now, updated_at: now };
      if (r.note) secret.notes = r.note;
      if (r.username) secret.fields.username = r.username;
      if (anySite) {
        let ctxId = sorted().find((id) => contextFor(items.get(id), s));
        if (!ctxId) {
          ctxId = newId();
          put(ctxId, s.pkg
            ? { kind: 'context', name, context_type: 'app', android_packages: [s.pkg], created_at: now, updated_at: now }
            : { kind: 'context', name: s.host, context_type: 'website', urls: [`${/^http:\/\//i.test(r.url) ? 'http' : 'https'}://${s.host}`], created_at: now, updated_at: now });
        }
        secret.contexts = [ctxId];
      }
      const id = newId();
      put(id, secret);
      Object.assign(line, { action: 'add', id, differs: !!sameUser });
    }
    lines.push(line);
  }
  return { writes, lines };
}
