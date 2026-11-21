// Encrypted storii backups (internal/vault/backup.go has the format): every item's plaintext keyed by id, sealed with
// a key derived from a backup password like the login keys (Argon2id + HKDF "storii wrap"), with AAD "storii:backup".
import { deriveKeys, newKdf, seal, open } from './crypto.js';

const te = new TextEncoder();
const td = new TextDecoder();
export const BACKUP_VERSION = 1;
export const WRONG_PASSWORD = 'Wrong backup password, or the file is damaged.';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isBackup(text) {
  try {
    return JSON.parse(text)?.storii_backup > 0;
  } catch {
    return false;
  }
}

// items: { id: item }. Returns the file's text.
export async function sealBackup(password, items, { kdf = newKdf(), now = new Date(), nonce } = {}) {
  const { wrap } = await deriveKeys(password, kdf);
  const data = await seal(wrap, te.encode(JSON.stringify({ items })), 'storii:backup', nonce);
  return JSON.stringify({ storii_backup: BACKUP_VERSION, exported_at: now.toISOString().replace(/\.\d+Z$/, 'Z'), kdf, data }, null, 2);
}

// Returns { id: item }.
export async function openBackup(password, text) {
  let b;
  try {
    b = JSON.parse(text);
  } catch {
    throw new Error('Not a storii backup.');
  }
  if (!(b?.storii_backup > 0)) throw new Error('Not a storii backup.');
  if (b.storii_backup !== BACKUP_VERSION) throw new Error(`This backup (version ${b.storii_backup}) needs a newer storii.`);
  const { wrap } = await deriveKeys(password, b.kdf);
  let plain;
  try {
    plain = await open(wrap, b.data, 'storii:backup');
  } catch {
    throw new Error(WRONG_PASSWORD);
  }
  return JSON.parse(td.decode(plain)).items || {};
}

// Which of the backup's items to add to a vault that has the ids in `have` (ones it has are left alone).
export function restorePlan(backupItems, have) {
  const add = [];
  let skipped = 0;
  for (const [id, it] of Object.entries(backupItems)) {
    const ok = UUID.test(id) && (it?.kind === 'secret' || it?.kind === 'context') && typeof it.name === 'string' && it.name;
    if (!ok || have.has(id)) skipped++;
    else add.push([id, it]);
  }
  add.sort(([, a], [, b]) => a.name.localeCompare(b.name));
  return { add, skipped };
}
