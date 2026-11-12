# storii

A small, self-hosted, zero-knowledge secret manager: passwords, 2FA codes, API keys and notes. They are filled in
where you need them by a browser extension and apps for Android, iOS and macOS. Windows gets a tray search, and a
CLI covers the terminal.

> storii is a personal project and hasn't had a security audit. Read [docs/CRYPTO.md](docs/CRYPTO.md) before
> trusting it with anything important.

## What's in it

- **Secret types**:
  - passwords
  - 2FA / TOTP codes (RFC 6238; scan or paste `otpauth://` QR codes)
  - API keys
  - notes
  - payment cards (number, expiry, CVC; brand detection and a typo check)
  - passkeys (created and used by the browser extension; synced, and listed in every app)
  - custom fields on any of them
- **Contexts**: a website or app that secrets belong to. One secret can be in several contexts, e.g. an API key
  used by two services, or a login shared by `google.com` and the Gmail app. Autofill offers the secrets of the
  context matching the site or app you're on.
- **End-to-end encryption**: your master password never leaves your devices. The server stores only ciphertext,
  including names, types and context links. See [docs/CRYPTO.md](docs/CRYPTO.md).
- **Autofill everywhere**:

  | Client                                       | Fills                                                           | Saves new logins        |
  |----------------------------------------------|-----------------------------------------------------------------|-------------------------|
  | Browser extension (Chrome, Edge, Firefox)    | logins, 2FA codes (also split one-box-per-digit inputs) and cards; suggests strong passwords on sign-up and reset forms; passkeys | yes                     |
  | Android (Autofill service, apps and browsers)| logins, 2FA codes and cards, with inline keyboard suggestions   | yes                     |
  | iOS / iPadOS (AutoFill credential provider)  | passwords and 2FA codes (iOS 18+), in QuickType and the sheet   | no (iOS doesn't allow it) |
  | macOS (AutoFill credential provider)         | passwords and 2FA codes (macOS 15+) in Safari and apps; menu bar search | no (macOS doesn't allow it) |
  | Windows tray app                             | a hotkey search (Ctrl+Shift+Space) that copies (cards: number, Shift+Enter expiry, Ctrl+Enter CVC); kept out of clipboard history | no            |
  | CLI (Linux, macOS, Windows)                  | copies to the clipboard (cleared after 30 s) or prints          | `storii add`            |

- **Offline**: every client keeps an encrypted copy and unlocks without the server. Changes sync when online.
- **Moving from v1**: `storii migrate` brings over your old passwords ([docs/MIGRATING.md](docs/MIGRATING.md)).
- **Importing**: logins from Google Password Manager, Chrome, Firefox, Bitwarden or 1Password, 2FA codes from
  Authy, everything (logins, 2FA codes, cards, passkeys) from a Bitwarden JSON export, and logins, 2FA codes and
  cards from a 1Password .1pux export, on the phone or with the CLI (see below).

## Layout

| Path                    | What                                                                                       |
|-------------------------|--------------------------------------------------------------------------------------------|
| `cmd/storii-api`        | the server (Go, Postgres)                                                                  |
| `cmd/storii`            | the CLI                                                                                    |
| `cmd/storii-devserver`  | a throwaway server with embedded Postgres, for development                                 |
| `internal/vault`        | crypto, items, TOTP and matching; the reference implementation                             |
| `internal/legacy`       | reads and decrypts storii v1 data                                                          |
| `extension/`            | browser extension (Manifest V3, plain JS)                                                  |
| `android/`              | Android app (Kotlin, Compose) with the Autofill service                                    |
| `ios/`                  | iOS and macOS apps (SwiftUI) with AutoFill extensions; logic in the `ios/StoriiCore` package, which also builds on Linux |
| `cmd/storii-tray`       | the Windows tray app (Go, Win32); search ranking in `internal/quick`                       |
| `testdata/vectors.json` | shared crypto, TOTP and matching vectors, checked by the Go, JS, Kotlin and Swift tests     |
| `api/openapi.yaml`      | the HTTP API                                                                               |

## Running the server

```sh
cp .env.example .env   # set SERVERSECRET and DB_PASSWORD
docker compose up -d
```

Or run the binary next to any Postgres:

| Variable                     | Default   | Notes                                                                              |
|------------------------------|-----------|------------------------------------------------------------------------------------|
| `DATABASE_URL`               |           | or `DBHOST`, `DBPORT`, `DBNAME`, `DBUSER`, `DBPASS`, `DBSSLMODE`                    |
| `SERVERSECRET`               | required  | at least 16 random characters; `JWTSECRET` is accepted for v1 setups                |
| `REGISTRATION`               | `open`    | set `closed` once your accounts exist                                              |
| `SESSIONDAYS`                | `90`      | sessions expire after this many days unused                                        |
| `ADDRESS`                    | `:9999`   |                                                                                    |
| `TRUSTPROXY`                 | `false`   | `true` behind a reverse proxy (rate limits by `X-Forwarded-For`)                   |

Put it behind HTTPS. Migrations run on start. The v2 tables live next to v1's, so you can point v2 at your v1
database and migrate in place.

## Clients

Ready-made builds of the CLI, the server, the Windows tray app, the browser extensions and the Android app are on the
[releases page](https://github.com/b2dennis/storii/releases/latest). The server image is `ghcr.io/b2dennis/storii-api:2` (`:latest` is still v1).

**CLI** (or the `storii` binary from a release)

```sh
go install github.com/b2dennis/storii/cmd/storii@latest
storii register --server https://storii.example.com --user you   # or: storii login
storii add password github.com --user you --gen --url https://github.com
storii add totp GitHub --uri 'otpauth://totp/GitHub:you?secret=...&issuer=GitHub' --context github.com
storii get github.com          # copies the password
storii totp github             # prints the current code
storii ls --site gist.github.com
storii help
```

**Importing from Google Password Manager** (or Chrome, Firefox, Bitwarden, 1Password):

- On Android: in Google Password Manager, tap Settings › Export passwords and share the file to storii (or save it
  and choose it in storii › Settings › Import passwords). storii shows what it will add, imports, and deletes the file.
- On a computer: export from passwords.google.com (Settings › Export passwords), then
  `storii import Passwords.csv --dry-run`, `storii import Passwords.csv`, and delete the file.

**Everything from Bitwarden**, passkeys and cards included: in Bitwarden, Tools › Export vault, file format
`.json` (not "encrypted"). Import it on Android or with `storii import bitwarden_export.json`, then delete the file.

**Everything from 1Password** (logins, 2FA codes, cards; 1Password doesn't export passkeys, and archived items are
skipped): in the 1Password app, File › Export › your account, format 1PUX. Import it on Android or with
`storii import 1PasswordExport.1pux`, then delete the file.

**2FA codes from Authy**: Authy has no export, but under the GDPR Twilio has to give you your data. Email
privacy@twilio.com (or use the privacy request form on twilio.com) asking for a copy of your Authy authenticator
tokens in machine-readable form (GDPR Articles 15 and 20), with the phone number of your Authy account. The file you
get back holds each token's `encrypted_seed`, `salt`, `unique_iv` and `key_derivation_iterations`, encrypted with
your Authy backup password. Import it like any other export: storii asks for the backup password and decrypts the
codes on your device or computer (`storii import authy.json`). Lists of `otpauth://` links (from Aegis, 2FAS, or
tools that read Authy's data) work too. Keep Authy until every code works in storii.

Each login becomes a password with a website or app context; Android app logins (`android://…@com.example.app`)
get an app context, so autofill offers them in that app. Logins already in storii are skipped, so importing twice is
safe, and a login that matches one migrated from v1 fills in its missing username.

**Browser extension** (Chrome, Edge, Brave; Firefox 140+, Zen): it shows an icon in login fields and fills 2FA fields.
Ctrl+Shift+L fills the best match. After you sign in with a new password, it offers to save it.

- Firefox and Zen: open `storii-<version>-firefox.xpi` from a release (drag it into the window, or Add-ons › ⚙ ›
  Install Add-on From File). It's signed by Mozilla, so it stays installed, and it updates itself from the releases.
- Chrome and friends: unzip `storii-<version>-chrome.zip` (or run `just extension` for `extension/dist/chrome`) and
  load it in chrome://extensions with Developer mode on, "Load unpacked".

**Android** (10+): install `storii-<version>.apk` from a release (or build it with `just android`). In the app's
settings, make storii the autofill service. In Chrome, also choose Settings › Autofill services › "Autofill using
another service". Biometric unlock and QR scanning for 2FA are in the app; 2FA QR codes can also be read from a
screenshot.

**iOS** (18+) and **macOS** (15+): open the project generated by `cd ios && xcodegen generate` in Xcode and set your
team. The iOS targets (Storii, StoriiAutoFill) need the app group `group.sh.base2.storii`. The macOS targets
(StoriiMac, StoriiMacAutoFill) use `<team id>.sh.base2.storii`, which needs no registration. All four share the
keychain group `sh.base2.storii.shared`. Then turn on AutoFill from storii's settings, or in (System) Settings ›
General › AutoFill & Passwords. On the Mac, storii also has a menu bar search: click a secret to copy it, ⌥-click for the
username. 2FA QR codes are read from a pasted screenshot (⌃⇧⌘4) or an image file there.

**Windows** (10+): run `storii-tray.exe` from `storii-<version>-windows-amd64.zip` (or the ARM zip) in a release;
`just windows` builds it too. It isn't code-signed, so SmartScreen asks once (More info › Run anyway). Run it, and
log in from the window it opens (or use `storii login` first: they share the state file). Ctrl+Shift+Space opens
the search from anywhere:

- Enter copies the password, 2FA code, API key or note.
- Shift+Enter copies the username.
- Ctrl+Enter copies the 2FA code of a login, when a 2FA secret shares its context.
- Ctrl+O opens the site.
- Esc clears the search, then closes.

Copies are kept out of clipboard history and cloud clipboard, and are cleared after 30 s. The vault locks after 10
minutes without use, and when Windows locks or sleeps. To change the hotkey or the timings, edit
`%AppData%\storii\tray.json` (from the tray menu) and restart. The tray menu also has "Start with Windows".

## Development

```sh
just dev    # server on :9999 with embedded Postgres
just test   # Go, extension, Android and iOS-core unit tests (and a Windows build of the tray app)
ios/mac-build              # iOS Simulator and macOS builds on a Mac, from a Linux box, via mac-run
ios/mac-shots STATE PW     # iOS Simulator screenshots of a vault state file (debug builds)
just e2e    # extension in Chromium and Firefox against `just dev`, plus CLI interop and the Swift round trip
just dist   # release files in build/dist (CLI and server tarballs, Windows zips, extensions, APK, SHA256SUMS)
just firefox-sign  # Mozilla-signed .xpi and its update manifest (needs an addons.mozilla.org API key)
just image  # server image to ghcr.io/b2dennis/storii-api:<version> and :2, with ko
```

All clients implement the same format. When you change it, update `docs/CRYPTO.md`, edit the inputs in
`testdata/vectors.json`, run `just vectors`, and make every client's tests pass again.

## License

See [LICENSE](LICENSE). The vendored Argon2 reference code in `ios/StoriiCore/Sources/CArgon2` is CC0 / Apache 2.0.
