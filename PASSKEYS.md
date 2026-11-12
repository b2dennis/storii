# Fix first: Windows tray can't unlock (reported 2026-11-07) — FIX MADE 2026-11-12, unverified on Windows

Cause found: popup window lacked WS_CLIPCHILDREN, so its repaint drew the field box over the password edit.

The tray's popup shows "storii is locked · dennis on storii.lab.base2.sh" with an empty box and
"Enter to continue · Esc to close", but there is no password field to type into, so the user is stuck. Started after
the 2.x updates / prod migration. To check: the locked-state view (does it render the input? focus? a password field
hidden because a session/key state is half-present, e.g. session valid but local key missing?); test unlock with an
existing session, after lock, after restart. Add a regression test for the locked view.

# DONE 2026-11-12: suggest a new password — extension picker (e2e) and Android autofill ("Use a strong password" on new/repeat fields, saved on submit, updates the login on reset forms; unit-tested, not tried on a device).

On "choose a new password" forms (signup, password reset, change password), focusing the field should pop up a
storii suggestion: a generated strong password, one click fills both "password" and "repeat password", and storii
saves it (update the existing login for that site/username, or a new one) once the form is submitted. Detect via
autocomplete="new-password", a second password field with the same value expected ("repeat"/"confirm"), or
password fields on pages without a username+current-password pair. Example: Purelymail reset page
(purelymail.com, reset code + PASSWORD + REPEAT PASSWORD) — its strength meter wants "1 century to crack", so use
long generated passwords (20+ chars, all classes). Same on Android autofill (save + generate) later.
Add a fixture page to the Chrome and Firefox e2e tests.

# DONE 2026-11-12: credit cards — `card` type in Go/CLI/tray, extension (popup + checkout fill incl. payment
# iframes, never foreign frames; offers to save a card typed at checkout, e2e), Android (UI + autofill), iOS/macOS
# views, Bitwarden JSON import (CLI + Android), 1Password .1pux import (CLI + Android: logins, 2FA, cards; shared
# cases testdata/import/1password*.json; CLI run against the dev server; not tried with a real 1Password export).

A `card` secret type: cardholder name, number, expiry (MM/YY), CVC, brand (detected from the number), optional
billing address / notes. Shown masked (•••• 4242) with copy buttons; Luhn check on entry.
- Autofill: browser extension fills checkout forms (autocomplete="cc-name|cc-number|cc-exp|cc-exp-month|
  cc-exp-year|cc-csc", plus heuristics for field names and split month/year selects, iframes of Stripe etc. need
  all_frames content scripts); offer to save a card typed into a checkout form. Android autofill: the same hints
  (AUTOFILL_HINT_CREDIT_CARD_*). iOS 17+: credit-card AutoFill isn't open to third parties for Safari forms; keep
  to copy/paste there. Windows tray: copy number/expiry/CVC.
- Always ask (and require unlock/biometrics) before filling a card, never fill silently.
- Import: Bitwarden/1Password exports and the Chrome payment-methods CSV if one exists; Google Pay cards can't be
  exported (CVC never). Shared test data for brand detection + Luhn in testdata/cards.json (Go, Kotlin, Swift, TS).

# DONE 2026-11-12: save prompt survives redirects (e2e covers a cross-host redirect)

Pages that navigate right after login submit (full-page redirect) show the extension's "save this password?"
prompt only for a moment. Fix: on submit, the content script hands the captured login to the service worker
(pending save per tab, with origin + timestamp, kept in chrome.storage.session); the next page load in that tab
(same site or within ~a minute, any URL) re-shows the prompt; drop it after save/dismiss/timeout. Add an e2e
case with a page that redirects on submit.

# MOSTLY DONE 2026-11-12: less disruptive unlocking
Done: unlocking inline from the page picker (2026-11-12): "Unlock storii" turns the picker into an extension frame
(web_accessible unlock/unlock.html, dynamic URL in Chrome) with the master password and "Use passkey"; the page can't
read it; Chrome e2e covers it, Firefox untested. Android autofill unlock is a translucent overlay (biometric prompt only, or a bottom sheet with the master
password) — builds, not tried on a device (emulator crashes on this VM). Browser: passkey unlock via WebAuthn PRF
(popup Settings toggle; locked popup asks right away), e2e with Chromium's virtual authenticator. Open: Firefox
support for WebAuthn in moz-extension pages (untested), whether the Windows Hello dialog closes the action popup,
passkey unlock inside the picker frame (falls back to the popup when the page's permissions policy forbids it).

- Android: unlocking from autofill opens the main app and comes back. Unlock in place instead: the autofill
  auth activity becomes a small dialog-style activity (translucent theme) with a BiometricPrompt (biometric key
  in the Android Keystore wrapping the vault key) and a password fallback, then returns the dataset directly.
- Browser extension: no biometrics in WebExtensions directly. Options: (a) WebAuthn PRF extension: register a
  platform passkey (Windows Hello / Touch ID / Android) for the extension origin and use the PRF output to wrap
  the vault key; unlock = one biometric prompt. Works in Chrome; Firefox supports PRF since 135 (check Zen and
  extension-origin support). (b) native messaging to the desktop app (tray on Windows, menu bar app on macOS)
  which unlocks via Windows Hello / Touch ID. Prefer (a), fall back to password. Also a longer, configurable
  auto-lock and "unlock with PIN" are cheaper wins.
- Unlocking from the page (inline in the autofill menu) instead of opening the popup.

# Passkeys: STEPS 1–4 + Bitwarden import DONE 2026-11-12
Released in 2.2.0: extension (Chrome e2e verified by SimpleWebAuthn; Firefox untested). After 2.2.0 (uncommitted):
Android Credential Manager provider (core/Passkey.kt, passkey/*; unit-tested, not tried on a device), iOS/macOS
AutoFill passkeys (StoriiCore Passkey.swift tested on Linux, app compiles; not tried on a device), Bitwarden JSON
import of logins, 2FA codes, cards and passkeys (Go + Kotlin, shared cases testdata/import/bitwarden*.json; not yet
tried with a real Bitwarden export). Open: CXP import, Windows (5).
Done: `passkey` type everywhere (Go/CLI/tray/Android/iOS list it read-only; Android edit keeps its fields), extension
creates/uses passkeys via a MAIN-world navigator.credentials hook + approval window (fallback to the browser's own
dialog; conditional mediation left to the browser). Open: Android Credential Manager provider (step 2), iOS (step 4),
Windows (5), Bitwarden/CXP import, shared Go/Kotlin/Swift passkey signing code (only JS signs today).

# Passkeys plan (original)

Status today (2.1.0): storii has no passkey support. The importers bring over passwords (CSV) and 2FA codes
(Authy, otpauth://) only. Google Password Manager's CSV export doesn't include passkeys at all; they leave Google
only through the FIDO Credential Exchange flow (see Import).

## 1. Core: a `passkey` secret type (Go + Kotlin + Swift, shared vectors)
- Fields: `credentialId` (b64url), `rpId`, `userHandle` (b64url), `userName`, `userDisplayName`, `privateKey`
  (ES256, PKCS#8 b64url), `createdAt`. Linked to the website context for `rpId` (create one like the CSV importer does).
- Sign count is always 0 (synced passkeys); flags UP|UV|BE|BS; AAGUID: pick a fixed storii AAGUID.
- `internal/passkey` (Go): create (keypair, attestation "none", authData with attested credential data, minimal CBOR
  for the COSE key + attestationObject) and assert (authData + clientDataHash, ECDSA P-256 sign).
- Shared vectors `testdata/passkey/*.json`; Go test verifies with go-webauthn (test-only dep); Kotlin/Swift ports
  check against the same vectors.
- Server is unaffected: it's just another encrypted item type. Show passkeys in all clients' lists (no secret shown,
  only rpId/user), allow delete.

## 2. Android (biggest win, Credential Manager, API 34+)
- `CredentialProviderService` (androidx.credentials): `onBeginCreateCredentialRequest` /
  `onBeginGetCredentialRequest` → PendingIntent to an unlock activity that builds the response
  (`CreatePublicKeyCredentialResponse` / `PublicKeyCredential` JSON). Privileged-browser allowlist for origins
  (Chrome/Firefox/Zen JSON from Google's sample); app origins via `android:apk-key-hash:`.
- Register in manifest with `android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE`; settings screen points users to
  "Passwords, passkeys & accounts" to enable storii.

## 3. Browser extension (Chrome + Firefox/Zen)
- Main-world script overrides `navigator.credentials.create/get` for `publicKey` requests, messages the content
  script → service worker → popup-style prompt ("Save passkey in storii" / pick one); falls back to the original
  call if the user declines or the vault is locked. Same approach as Bitwarden. Reuse the Go/TS signing logic via a
  TS port + the shared vectors (WebCrypto ECDSA P-256; convert DER→raw? No: WebAuthn wants DER, WebCrypto gives raw
  r||s → convert to DER).
- e2e: puppeteer test against a local page using a tiny WebAuthn RP (go-webauthn in a test server).

## 4. iOS/macOS (17+)
- AutoFill extension: `prepareInterfaceForPasskeyRegistration`, `provideCredentialWithoutUserInteraction(for:
  ASPasskeyCredentialRequest)`, `prepareCredentialList(for:requestParameters:)`; save
  `ASPasskeyCredentialIdentity` to `ASCredentialIdentityStore`. Info.plist: `ProvidesPasskeys = YES`.
  Build/verify on the Mac via mac-run.

## 5. Windows tray
- Windows 11 passkey plugin API (WebAuthn plugin authenticator, 24H2+/25H2). Later; low priority.

## Import
- Bitwarden JSON export: `fido2Credentials` (keyValue = PKCS#8 b64url) → direct import. Add to `storii import`
  and the Android import screen, with shared test data.
- FIDO CXF/CXP (Credential Exchange): Android Credential Manager import API and iOS 26
  `ASCredentialImportManager` let users move passkeys out of Google PM / iCloud Keychain into storii. Do this after
  the provider work (needs the provider registered). Check current API status before starting.

## Order
1 → 2 → 3 → import (Bitwarden, then CXP) → 4 → 5. Release as 2.2.0 after 1–3.
