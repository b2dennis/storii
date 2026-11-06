# storii v2 cryptography

The server never sees the master password, a key that can decrypt anything, or any plaintext: not item names,
not types, not which secrets belong to which context. Every client (Go CLI, browser extension, Android, iOS)
implements the scheme below and is checked against the same vectors in `testdata/vectors.json`.

## Keys

```
password'  = NFC(master password), UTF-8
masterKey  = Argon2id(password', salt, t=3, m=64 MiB, p=2, 32 bytes)     (parameters stored per account as "kdf")
authKey    = HKDF-SHA256(masterKey, salt = empty, info = "storii auth", 32 bytes)
wrapKey    = HKDF-SHA256(masterKey, salt = empty, info = "storii wrap", 32 bytes)
vaultKey   = 32 random bytes, made once at registration
```

- **authKey** is what a client sends to log in. The server stores only SHA-256(authKey) and compares in constant
  time. It can't be turned back into the master password or the wrapKey (HKDF with different info strings).
- **wrapKey** never leaves the device. It encrypts the vault key: `wrapped_key = seal(wrapKey, vaultKey, "storii:vault-key")`.
- **vaultKey** encrypts every item. Changing the master password only re-wraps it, so nothing is re-encrypted.
- The salt is 16 random bytes per account. `POST /api/v2/prelogin` hands out the KDF parameters, with a stable
  fake salt for unknown usernames so it doesn't reveal which accounts exist.
- NFC normalization makes "ä" typed as one code point or as "a" plus a combining diaeresis the same password
  (macOS and iOS keyboards can produce either).

## Envelope

```
seal(key, plaintext, aad) = base64( 0x01 || nonce(12, random) || AES-256-GCM(key, nonce, plaintext, aad) || tag(16) )
```

The leading byte is a version, so the format can change later. The AAD binds a ciphertext to its role:

| What          | AAD                  |
|---------------|----------------------|
| wrapped key   | `storii:vault-key`   |
| item          | `storii:item:<id>`   |

Binding items to their id means the server can't swap ciphertexts between items without detection.

## Items

Each item is a JSON document, encrypted as a whole. Empty values are left out (like Go's `omitempty`).

```json
{"kind": "secret", "name": "GitHub", "type": "password",
 "contexts": ["<context item id>", "..."],
 "fields": {"username": "dennis", "password": "..."},
 "custom": [{"name": "PIN", "value": "1234", "hidden": true}],
 "notes": "...", "created_at": "2026-11-05T10:00:00Z", "updated_at": "..."}

{"kind": "context", "name": "GitHub", "context_type": "website",
 "urls": ["https://github.com"], "android_packages": ["com.github.android"]}
```

Secret types and their fields:

| type       | fields                                                                   | "copy" gives      |
|------------|--------------------------------------------------------------------------|-------------------|
| `password` | `username`, `password`                                                   | the password      |
| `totp`     | `secret` (base32), `issuer`, `account`, `algorithm`, `digits`, `period`  | the current code  |
| `api_key`  | `key`, `key_id`                                                          | the key           |
| `note`     | (the text is in `notes`)                                                 | the note          |

TOTP is RFC 6238. The defaults are SHA1, 6 digits and 30 s, and defaults are left out of the fields.
`otpauth://totp/...` URIs from 2FA QR codes are parsed into these fields.

A context is a website or app. Secrets point to contexts by id, so one secret can be in several contexts. Autofill offers
the secrets of every context that matches:

- **Websites**: the page's host equals the context URL's host, or is a subdomain of it. The port and a leading
  `www.` are ignored, so `https://www.google.com` matches `accounts.google.com`, but `github.com` doesn't match
  `github.com.evil.io`.
- **Android apps**: the package name matches exactly. In a browser, only the web domain counts, never the
  browser's own package.
- **iOS apps** are matched through their associated domains, which iOS reports as web domains.

## Sync

Items are stored as `(id, ciphertext, revision)`, where the revision is a per-account counter that every write
bumps. `GET /api/v2/sync?since=N` returns what changed after N, with deletions as tombstones. With `since=0` it
returns a full snapshot without tombstones, and clients replace their local copy with it. Concurrent edits are
last writer wins.

## Local storage

Clients keep the session token and the still-encrypted items. That is enough to unlock offline, but useless
without the master password. Each client handles the vault key like this:

- **CLI**: never stored. It asks for the master password every time, or reads `STORII_PASSWORD` in scripts.
- **Browser extension**: in `storage.session` (memory only) until it auto-locks.
- **Android**: in memory, and with biometric unlock in an Android Keystore key that needs BIOMETRIC_STRONG and is
  invalidated when enrollments change.
- **iOS**: in memory, and with Face ID in a Keychain item with `.biometryCurrentSet`, shared with the AutoFill
  extension through a keychain access group.

## What the server can still see

- Usernames.
- How many items an account has, their sizes and when they change.
- Device names and IP addresses.

It can also refuse or roll back writes. Encryption makes that detectable per item but not across the whole vault.

## storii v1

v1 sent the master password to the server at login, and the server stored it as a bcrypt hash. Each password was
encrypted with its own Argon2id key derived from that same master password. The v1 CLI also kept the master
password **in plaintext** in its config file. `storii migrate` reads v1 data, decrypts it locally and
re-encrypts it as v2 items (see docs/MIGRATING.md).
