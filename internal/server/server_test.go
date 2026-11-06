package server_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/legacy"
	"github.com/b2dennis/storii/internal/server"
	"github.com/b2dennis/storii/internal/store"
	"github.com/b2dennis/storii/internal/vault"
)

type env struct {
	url string
	dsn string
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newEnv(t *testing.T, cfg server.Config) env {
	t.Helper()
	if testing.Short() {
		t.Skip("needs embedded postgres")
	}
	port := freePort(t)
	dir := t.TempDir()
	pg := embeddedpostgres.NewDatabase(embeddedpostgres.DefaultConfig().Port(uint32(port)).
		Database("storii").Username("storii").Password("pw").
		RuntimePath(filepath.Join(dir, "rt")).DataPath(filepath.Join(dir, "data")).Logger(io.Discard))
	if err := pg.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pg.Stop() })
	dsn := fmt.Sprintf("postgres://storii:pw@localhost:%d/storii?sslmode=disable", port)
	db, err := store.Open(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	if cfg.Secret == nil {
		cfg.Secret = []byte("test-secret-test-secret")
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = time.Hour
	}
	if cfg.AuthBurst == 0 {
		cfg.AuthRate, cfg.AuthBurst = 1000, 1000
	}
	ts := httptest.NewServer(server.New(db, cfg, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))))
	t.Cleanup(ts.Close)
	return env{ts.URL, dsn}
}

func raw(t *testing.T, method, url, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, url, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestVaultLifecycle(t *testing.T) {
	e := newEnv(t, server.Config{Registration: true})
	ctx := context.Background()

	st, v, err := client.Register(ctx, e.url, "dennis", "Correct-Horse-42", "test A")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.Register(ctx, e.url, "Dennis", "Other-Password-1", "x"); err == nil {
		t.Fatal("usernames must be unique case-insensitively")
	}

	// A context with a password, a TOTP and an API key; the API key also belongs to a second context.
	gh, err := v.PutOne(ctx, "", vault.Item{Kind: vault.KindContext, Name: "GitHub", ContextType: vault.ContextWebsite,
		URLs: []string{"https://github.com"}, AndroidPackages: []string{"com.github.android"}})
	if err != nil {
		t.Fatal(err)
	}
	ci, _ := v.PutOne(ctx, "", vault.Item{Kind: vault.KindContext, Name: "CI", ContextType: vault.ContextOther})
	pw, _ := v.PutOne(ctx, "", vault.Item{Kind: vault.KindSecret, Type: vault.TypePassword, Name: "GitHub login",
		Contexts: []string{gh}, Fields: map[string]string{"username": "dennis", "password": "s3cret"}})
	totp, _ := vault.ParseOTPAuth("otpauth://totp/GitHub:dennis?secret=JBSWY3DPEHPK3PXP&issuer=GitHub")
	otp, err := v.PutOne(ctx, "", vault.Item{Kind: vault.KindSecret, Type: vault.TypeTOTP, Name: "GitHub 2FA",
		Contexts: []string{gh}, Fields: totp.Fields()})
	if err != nil {
		t.Fatal(err)
	}
	key, _ := v.PutOne(ctx, "", vault.Item{Kind: vault.KindSecret, Type: vault.TypeAPIKey, Name: "GitHub token",
		Contexts: []string{gh, ci}, Fields: map[string]string{"key": "ghp_x"}})
	if _, err := v.PutOne(ctx, "", vault.Item{Kind: vault.KindSecret, Type: "bogus", Name: "x"}); err == nil {
		t.Fatal("invalid items must be rejected client-side")
	}

	// The server only has ciphertext.
	conn, _ := pgx.Connect(ctx, e.dsn)
	defer conn.Close(ctx)
	var leaked int
	conn.QueryRow(ctx, `SELECT count(*) FROM items WHERE data LIKE '%GitHub%' OR data LIKE '%s3cret%'`).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("plaintext on the server")
	}

	// A second device sees everything.
	st2, v2, err := client.Login(ctx, e.url, "DENNIS", "Correct-Horse-42", "test B")
	if err != nil {
		t.Fatal(err)
	}
	if n := len(v2.Items); n != 5 {
		t.Fatalf("second device has %d items", n)
	}
	if got := v2.ForSite("gist.github.com", ""); len(got) != 3 {
		t.Fatalf("site match: %d", len(got))
	}
	if got := v2.ForSite("", "com.github.android"); len(got) != 3 {
		t.Fatalf("app match: %d", len(got))
	}
	if _, _, err := client.Login(ctx, e.url, "dennis", "wrong-password-1A", "x"); !client.IsUnauthorized(err) {
		t.Fatalf("wrong password: %v", err)
	}

	// Deleting a context unlinks it, and the second device sees the change incrementally.
	if err := v.Delete(ctx, ci); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, pw); err != nil {
		t.Fatal(err)
	}
	before := st2.Revision
	if err := v2.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if st2.Revision <= before || len(v2.Items) != 3 || !slices.Equal(v2.Items[key].Contexts, []string{gh}) {
		t.Fatalf("after refresh: rev %d items %d contexts %v", st2.Revision, len(v2.Items), v2.Items[key].Contexts)
	}
	// The first device has only ever done a full sync (revision 0) and wrote its items itself. Its next sync is a full
	// snapshot without tombstones, which must still drop what other devices deleted.
	if st.Revision != 0 {
		t.Fatalf("first device revision %d, want 0 for this check", st.Revision)
	}
	if err := v2.Delete(ctx, otp); err != nil {
		t.Fatal(err)
	}
	if err := v.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Items[otp]; ok || len(v.Items) != 2 {
		t.Fatalf("first device kept a deleted item: %d items", len(v.Items))
	}
	if err := v2.Refresh(ctx); err != nil {
		t.Fatal(err)
	}

	// A full sync leaves tombstones out.
	_, items, _ := st2.API().Sync(ctx, 0)
	if len(items) != 2 {
		t.Fatalf("full sync returned %d items", len(items))
	}

	// Offline unlock from the saved state.
	path := filepath.Join(t.TempDir(), "state.json")
	st2.Save(path)
	again, _ := client.LoadState(path)
	if v3, err := again.Unlock("Correct-Horse-42"); err != nil || len(v3.Items) != 2 {
		t.Fatalf("offline unlock: %v", err)
	}
	if _, err := again.Unlock("nope"); err == nil {
		t.Fatal("unlocked with a wrong password")
	}

	// Changing the master password keeps the data and signs out other devices.
	if err := v.ChangePassword(ctx, "New-Horse-Battery-7"); err != nil {
		t.Fatal(err)
	}
	if err := st2.Pull(ctx); !client.IsUnauthorized(err) {
		t.Fatalf("other device still signed in: %v", err)
	}
	if err := st.Pull(ctx); err != nil {
		t.Fatal("this device should stay signed in:", err)
	}
	_, v4, err := client.Login(ctx, e.url, "dennis", "New-Horse-Battery-7", "test C")
	if err != nil || len(v4.Items) != 2 {
		t.Fatalf("login with new password: %v", err)
	}
	if _, _, err := client.Login(ctx, e.url, "dennis", "Correct-Horse-42", "x"); err == nil {
		t.Fatal("old password still works")
	}

	// Server-side validation.
	tok := st.Token
	for _, body := range []any{
		map[string]any{"writes": []any{map[string]any{"id": "not-a-uuid", "data": "AAAA"}}},
		map[string]any{"writes": []any{map[string]any{"id": gh}}},
		map[string]any{"writes": []any{}},
		map[string]any{"writes": []any{map[string]any{"id": gh, "data": "AAAA"}, map[string]any{"id": gh, "delete": true}}},
	} {
		if code, _ := raw(t, "POST", e.url+"/api/v2/items", tok, body); code != 400 {
			t.Errorf("%v: %d", body, code)
		}
	}
	if code, _ := raw(t, "GET", e.url+"/api/v2/sync", "", nil); code != 401 {
		t.Errorf("unauthenticated sync: %d", code)
	}

	// Sessions can be listed and revoked.
	var sess struct {
		Sessions []store.Session `json:"sessions"`
	}
	st.API().Get(ctx, "/api/v2/sessions", &sess)
	if len(sess.Sessions) != 2 {
		t.Fatalf("sessions: %+v", sess.Sessions)
	}
	for _, s := range sess.Sessions {
		if !s.Current {
			if code, _ := raw(t, "DELETE", e.url+"/api/v2/sessions/"+s.ID, tok, nil); code != 204 {
				t.Fatal("revoke", code)
			}
		}
	}

	// Deleting the account needs the master password.
	if code, _ := raw(t, "DELETE", e.url+"/api/v2/account", tok, map[string]string{"auth_key": st2.Token}); code != 403 {
		t.Fatal("delete with wrong key", code)
	}
	if err := st.API().DeleteAccount(ctx, v.AuthKey()); err != nil {
		t.Fatal(err)
	}
	if err := st.Pull(ctx); !client.IsUnauthorized(err) {
		t.Fatal("deleted account still works")
	}
}

func TestPreloginAndRegistration(t *testing.T) {
	e := newEnv(t, server.Config{Registration: false, AuthRate: 0.001, AuthBurst: 4})
	api := client.NewAPI(e.url, "")
	ctx := context.Background()
	k1, _ := api.Prelogin(ctx, "nobody")
	k2, _ := api.Prelogin(ctx, "NoBody")
	k3, _ := api.Prelogin(ctx, "someone")
	if k1.Salt != k2.Salt || k1.Salt == k3.Salt || k1.Validate() != nil {
		t.Fatal("fake salts must be stable per name and valid")
	}
	if _, _, err := client.Register(ctx, e.url, "dennis", "Correct-Horse-42", "x"); err == nil {
		t.Fatal("registration is closed")
	}
	// Burst of 4 used up by 3 prelogins and the register: now rate limited.
	code, _ := raw(t, "POST", e.url+"/api/v2/login", "", map[string]string{"username": "a"})
	if code != http.StatusTooManyRequests {
		t.Fatal("expected rate limiting, got", code)
	}
}

// encryptV1 is storii v1's crypto.EncryptPassword, byte for byte in behaviour.
func encryptV1(secret, master string) legacy.Password {
	salt, iv := make([]byte, 16), make([]byte, 12)
	rand.Read(salt)
	rand.Read(iv)
	key := argon2.IDKey([]byte(master), salt, 3, 64*1024, 2, 32)
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	ct := gcm.Seal(nil, iv, []byte(secret), nil)
	return legacy.Password{Value: ct[:len(ct)-16], AuthTag: ct[len(ct)-16:], IV: iv, Salt: salt}
}

// v1Schema is what GORM's AutoMigrate created for v1 on Postgres.
const v1Schema = `
CREATE TABLE users (id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz, deleted_at timestamptz,
  username text NOT NULL UNIQUE, password_hash text NOT NULL);
CREATE TABLE stored_passwords (id bigserial PRIMARY KEY, created_at timestamptz, updated_at timestamptz,
  deleted_at timestamptz, user_id bigint NOT NULL, name text NOT NULL, value bytea NOT NULL, iv bytea NOT NULL,
  auth_tag bytea NOT NULL, salt bytea NOT NULL, associated_url text);`

func TestMigrateFromV1(t *testing.T) {
	e := newEnv(t, server.Config{Registration: true})
	ctx := context.Background()
	const master = "Old-Master-Password-1"

	// A v1 database next to the v2 tables, as when v2 is deployed on the same database.
	conn, err := pgx.Connect(ctx, e.dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, v1Schema); err != nil {
		t.Fatal(err)
	}
	conn.Exec(ctx, `INSERT INTO users (username, password_hash) VALUES ('dennis', 'x'), ('other', 'y')`)
	entries := []struct{ name, secret, url, user string }{
		{"gmail", "gm-pw-1", "https://mail.google.com", "dennis"},
		{"github.com", "gh-pw ü", "", "dennis"},
		{"wifi at home", "wlan-pass", "", "dennis"},
		{"google", "google-pw", "https://accounts.google.com/signin", "dennis"},
		{"someone else's", "nope", "", "other"},
	}
	for _, en := range entries {
		p := encryptV1(en.secret, master)
		conn.Exec(ctx, `INSERT INTO stored_passwords (user_id, name, value, iv, auth_tag, salt, associated_url)
			VALUES ((SELECT id FROM users WHERE username = $1), $2, $3, $4, $5, $6, $7)`,
			en.user, en.name, p.Value, p.IV, p.AuthTag, p.Salt, en.url)
	}
	conn.Exec(ctx, `INSERT INTO stored_passwords (user_id, name, value, iv, auth_tag, salt, deleted_at)
		SELECT user_id, 'deleted one', value, iv, auth_tag, salt, now() FROM stored_passwords LIMIT 1`)

	pws, err := legacy.FromDB(ctx, e.dsn, "dennis")
	if err != nil {
		t.Fatal(err)
	}
	if len(pws) != 4 {
		t.Fatalf("read %d v1 passwords", len(pws))
	}
	if r := legacy.Convert("dennis", pws, "wrong", time.Now()); len(r.Failed) != 4 {
		t.Fatal("wrong master password decrypted something")
	}
	res := legacy.Convert("dennis", pws, master, time.Now())
	if len(res.Failed) != 0 {
		t.Fatal(res.Failed)
	}

	_, v, err := client.Register(ctx, e.url, "dennis", "New-Master-Password-2", "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Put(ctx, res.Items); err != nil {
		t.Fatal(err)
	}
	// Converting again yields the same ids: re-running the migration doesn't duplicate anything.
	again := legacy.Convert("dennis", pws, master, time.Now())
	for id := range again.Items {
		if _, ok := v.Items[id]; !ok {
			t.Fatal("ids are not deterministic")
		}
	}

	_, v2, err := client.Login(ctx, e.url, "dennis", "New-Master-Password-2", "check")
	if err != nil {
		t.Fatal(err)
	}
	secrets := v2.List(vault.KindSecret)
	if len(secrets) != 4 || len(v2.List(vault.KindContext)) != 3 {
		t.Fatalf("%d secrets, %d contexts", len(secrets), len(v2.List(vault.KindContext)))
	}
	byName := map[string]client.Entry{}
	for _, s := range secrets {
		byName[s.Name] = s
	}
	if byName["github.com"].Field("password") != "gh-pw ü" || byName["wifi at home"].Field("password") != "wlan-pass" {
		t.Fatal("passwords didn't survive")
	}
	if got := v2.ForSite("github.com", ""); len(got) != 1 || got[0].Name != "github.com" {
		t.Fatal("domain-named entry should get a context")
	}
	if len(byName["wifi at home"].Contexts) != 0 {
		t.Fatal("non-domain names get no context")
	}
	if got := v2.ForSite("mail.google.com", ""); len(got) != 1 {
		t.Fatalf("mail.google.com: %d", len(got))
	}

	// The same through a v1 API (a stand-in that answers like v1 did).
	v1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/login":
			var b map[string]string
			json.NewDecoder(r.Body).Decode(&b)
			if b["password"] != master {
				w.WriteHeader(401)
				w.Write([]byte(`{"error":"Unauthorized"}`))
				return
			}
			w.Write([]byte(`{"data":{"token":"tok","user_id":1,"username":"dennis"}}`))
		case "/password":
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(401)
				return
			}
			var list []map[string]string
			for _, p := range pws {
				list = append(list, map[string]string{"name": p.Name, "value": hex.EncodeToString(p.Value),
					"iv": hex.EncodeToString(p.IV), "auth_tag": hex.EncodeToString(p.AuthTag),
					"salt": hex.EncodeToString(p.Salt), "associated_url": p.AssociatedURL})
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"passwords": list}})
		}
	}))
	defer v1.Close()
	viaAPI, err := legacy.FromServer(ctx, v1.URL, "dennis", master)
	if err != nil {
		t.Fatal(err)
	}
	if r := legacy.Convert("dennis", viaAPI, master, time.Now()); len(r.Items) != len(res.Items) || len(r.Failed) != 0 {
		t.Fatal("API path differs from DB path")
	}
	if _, err := legacy.FromServer(ctx, v1.URL, "dennis", "wrong"); err == nil {
		t.Fatal("wrong v1 password accepted")
	}
}
