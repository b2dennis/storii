# storii v2 plan

## Goals
1. Secret types: password, TOTP (2FA codes), API key, secure note; every type can carry extra custom fields.
2. Contexts: an app or website (name, URLs/domains, Android package names). A secret links to any number of
   contexts, and a context can hold several secrets (e.g. "GitHub" = password + TOTP + API key).
3. Native apps that autofill: Android (AutofillService), iOS (AutoFill credential provider incl. one-time codes),
   desktop browsers (Chrome/Firefox extension), plus the Go CLI.
4. Carry secrets over from a v1 database or server.

## Why the security model changes
v1 sends the master password to the server at login (it is also the bcrypt-hashed account password) and the CLI
stores it in plaintext in its config file. v2 is zero-knowledge:

- masterKey = Argon2id(master password, per-account salt, t=3, m=64 MiB, p=2) – same parameters as v1.
- authKey = HKDF-SHA256(masterKey, "storii auth") goes to the server; the server only stores SHA-256(authKey).
- A random 256-bit vault key encrypts every item (AES-256-GCM, AAD bound to the item id); it is stored on the server
  wrapped with HKDF(masterKey, "storii wrap"). Changing the master password re-wraps only that key.
- The server stores opaque blobs: item type, names, URLs and context links are all inside the ciphertext.
- Specified in docs/CRYPTO.md and pinned by testdata/vectors.json, which every client tests against.

## Server (Go, rewrite of the v1 server)
- net/http + pgx + embedded goose migrations; new tables (accounts, sessions, items) coexist with the v1 tables
  (users, stored_passwords), so v2 can run on the same database.
- API /api/v2: prelogin, register, login, logout, account, change password, delete account,
  GET /sync?since=rev, PUT /items (batch upsert/delete). Per-account revision counter, tombstones, last writer wins.
- Opaque revocable session tokens, per-IP rate limit on auth endpoints, REGISTRATION=open|closed.
- Tests against embedded Postgres; cmd/storii-devserver for local runs.

## Clients
- Go: internal/vault (crypto, schemas, TOTP, otpauth:// parsing, URL matching, generator), internal/client (sync).
  CLI `storii`: register/login/logout, ls/show/get/totp, add/edit/rm, gen, ctx, passwd, migrate.
- Browser extension (extension/, MV3, Chrome + Firefox): unlock popup, search, copy, TOTP, add/edit, in-page fill of
  login and one-time-code fields with an inline field icon and a keyboard shortcut.
- Android (android/, Kotlin/Compose, sh.base2.storii): vault UI, biometric unlock, AutofillService with
  locked-vault authentication flow, TOTP fill and save requests.
- iOS (ios/, SwiftUI + StoriiCore package that builds/tests on Linux): vault UI, Face ID unlock, AutoFill credential
  provider extension for passwords and one-time codes (iOS 18).

## Migration from v1
`storii migrate --legacy-db <postgres dsn> --legacy-user <name>` or `--legacy-server <url>`: decrypts each v1
password with the old master password, creates a password secret (plus a context from associated_url) and uploads
it. Item ids are derived from the v1 user and name, so re-running doesn't duplicate.

## Verification
go test (server, crypto, migration from real v1-format rows), node tests + Playwright e2e of the extension against the
dev server, Gradle unit tests + emulator autofill check, swift test on Linux + iOS build on the Mac.

## Status (2026-11-06)

Done and verified:
- Server, CLI and migration: Go tests, plus a real v1 server and database migrated by DB and API, re-runs idempotent.
- Extension: unit tests and Chromium e2e (fill, OTP, save, cross-site refusal, lock, CLI interop).
- Android: unit tests on the emulator, autofill in Chrome (fill, and save while locked and unlocked), and adding a
  username to a username-less login. A 2FA QR code read from a gallery image (photo picker, no permission needed),
  then saved.
- iOS core: `swift test` on Linux, vectors plus a live round trip.

- iOS app: built for the Simulator on the Mac (`ios/mac-build`) and run with a real vault state there
  (`ios/mac-shots`): locked screen, unlock, list with live 2FA codes, light and dark.
- macOS app, AutoFill extension and menu bar search (same Swift sources, `StoriiMac` targets): built on the Mac.
- Windows tray app (`cmd/storii-tray`): `internal/quick` unit tests, plus a run under Wine against the dev server:
  - login and sync, and a deletion made by the CLI arriving;
  - search, and the hotkey;
  - copying the password, username and related 2FA code, with the clipboard-history opt-out formats set;
  - clearing the clipboard after 30 s;
  - locking on suspend, a wrong password, unlocking;
  - dark mode and the embedded manifest.

Not verified:
- The iOS and macOS AutoFill extensions in action: they need a signed build on a device or Mac with AutoFill turned on.
- The macOS app running: it compiles, but wasn't opened (it would show on the owner's screen).
- The Windows tray app on real Windows (only under Wine): tray click and menu, "Start with Windows", per-monitor DPI.
