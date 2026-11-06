# Moving from storii v1

v2 is a new, zero-knowledge format with its own tables (`accounts`, `sessions`, `items`). It can share a database
with v1 without touching the v1 tables (`users`, `stored_passwords`), so you can run both while you move.

1. **Deploy v2**, either against the v1 database or a new one. Set `SERVERSECRET` (at least 16 characters;
   `JWTSECRET` is read as a fallback). Set `REGISTRATION=open` until you have created your account.
2. **Create a v2 account**, ideally with a new master password (v1's has been sent to the server and sits in the
   v1 CLI config):
   ```sh
   storii register --server https://storii.example.com --user dennis
   ```
3. **Migrate.** The CLI decrypts your v1 passwords locally and uploads them as v2 items. Either read them straight
   from the v1 database:
   ```sh
   storii migrate --legacy-db 'postgres://user:pass@host:5432/storii' --legacy-user dennis --dry-run
   storii migrate --legacy-db 'postgres://user:pass@host:5432/storii' --legacy-user dennis
   ```
   or through a running v1 server:
   ```sh
   storii migrate --legacy-server https://old-storii.example.com --legacy-user dennis
   ```
   If the v1 config (`~/.config/storii/config.json`, `%APPDATA%\storii\config.json`, or `~/.storii`) exists, its
   server, username and master password are used as defaults. Otherwise you are asked for the v1 master password.
4. **Check** with `storii ls` or any of the apps, then set `REGISTRATION=closed`.
5. **Clean up**: delete the v1 config file, which holds your old master password in plaintext. Once you no longer
   need v1, drop its tables (`DROP TABLE stored_passwords, users;`).

How entries are converted:

- Each v1 password becomes a `password` secret with the same name. It has no username, because v1 didn't store one,
  so add usernames as you go; autofill offers to fill them in on Android and in the browser.
- Its `associated_url`, or the name itself when it looks like a domain (`github.com`), becomes a website context.
  Entries for the same host share one context.
- Ids are derived from the v1 username and entry name, so running the migration again is safe. Entries migrated
  before are skipped, or replaced with `--overwrite`.
- An entry that can't be decrypted (e.g. one saved with a different master password) is listed and skipped. The
  others are still migrated.
