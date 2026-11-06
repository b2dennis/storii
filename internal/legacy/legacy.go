// Package legacy reads passwords from storii v1, either straight from its Postgres tables (users, stored_passwords)
// or through its HTTP API, and decrypts them with the v1 scheme: per password, key = Argon2id(master password,
// salt, t=3, m=64 MiB, p=2) and AES-256-GCM.
package legacy

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/argon2"
)

// Password is one v1 entry, still encrypted.
type Password struct {
	Name          string
	Value         []byte
	IV            []byte
	AuthTag       []byte
	Salt          []byte
	AssociatedURL string
}

// Decrypt opens a v1 password with the master password (in v1 that is also the account password).
func (p Password) Decrypt(masterPassword string) (string, error) {
	key := argon2.IDKey([]byte(masterPassword), p.Salt, 3, 64*1024, 2, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(p.IV) != gcm.NonceSize() {
		return "", errors.New("bad IV length")
	}
	pt, err := gcm.Open(nil, p.IV, append(bytes.Clone(p.Value), p.AuthTag...), nil)
	if err != nil {
		return "", errors.New("could not decrypt (wrong master password?)")
	}
	return string(pt), nil
}

// FromDB reads a user's passwords from a v1 database. Rows soft-deleted by GORM are skipped.
func FromDB(ctx context.Context, dsn, username string) ([]Password, error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	defer conn.Close(ctx)
	var userID int64
	err = conn.QueryRow(ctx, `SELECT id FROM users WHERE username = $1 AND deleted_at IS NULL`, username).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("no v1 user %q in that database", username)
	} else if err != nil {
		return nil, fmt.Errorf("read v1 users table: %w", err)
	}
	rows, err := conn.Query(ctx, `SELECT name, value, iv, auth_tag, salt, COALESCE(associated_url, '')
		FROM stored_passwords WHERE user_id = $1 AND deleted_at IS NULL ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Password, error) {
		var p Password
		err := r.Scan(&p.Name, &p.Value, &p.IV, &p.AuthTag, &p.Salt, &p.AssociatedURL)
		return p, err
	})
}

// FromServer logs in to a v1 server and lists the user's passwords.
func FromServer(ctx context.Context, baseURL, username, password string) ([]Password, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	hc := &http.Client{Timeout: 30 * time.Second}
	call := func(method, path, token string, body, out any) error {
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequestWithContext(ctx, method, baseURL+path, rd)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := hc.Do(req)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode >= 300 {
			return fmt.Errorf("%s %s: %s %s", method, path, res.Status, strings.TrimSpace(string(raw)))
		}
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			return err
		}
		return json.Unmarshal(env.Data, out)
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := call(http.MethodPost, "/user/login", "", map[string]string{"username": username, "password": password}, &login); err != nil {
		return nil, err
	}
	var rawList struct {
		Passwords []map[string]string `json:"passwords"`
	}
	if err := call(http.MethodGet, "/password", login.Token, nil, &rawList); err != nil {
		return nil, err
	}
	out := make([]Password, 0, len(rawList.Passwords))
	for _, m := range rawList.Passwords {
		p := Password{Name: m["name"], AssociatedURL: m["associated_url"]}
		var err error
		for _, f := range []struct {
			dst *[]byte
			key string
		}{{&p.Value, "value"}, {&p.IV, "iv"}, {&p.AuthTag, "auth_tag"}, {&p.Salt, "salt"}} {
			if *f.dst, err = hex.DecodeString(m[f.key]); err != nil {
				return nil, fmt.Errorf("password %q: bad %s", p.Name, f.key)
			}
		}
		out = append(out, p)
	}
	return out, nil
}
