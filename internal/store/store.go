// Package store is the server's Postgres layer.
package store

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/b2dennis/storii/internal/vault"
)

//go:embed migrations/*.sql
var migrations embed.FS

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("already exists")
)

type Store struct{ pool *pgxpool.Pool }

// Open connects and applies pending migrations.
func Open(ctx context.Context, url string) (*Store, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	sqldb := stdlib.OpenDBFromPool(pool)
	defer sqldb.Close()
	goose.SetBaseFS(migrations)
	goose.SetTableName("storii_goose_version") // don't collide with anything else living in a shared database
	if err := goose.SetDialect("postgres"); err != nil {
		return nil, err
	}
	goose.SetLogger(goose.NopLogger())
	if err := goose.UpContext(ctx, sqldb, "migrations"); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{pool}, nil
}

func (s *Store) Close()                         { s.pool.Close() }
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

type Account struct {
	ID         int64
	Username   string
	KDF        vault.KDF
	AuthHash   []byte
	WrappedKey string
	Revision   int64
	CreatedAt  time.Time
}

func Hash(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

func (s *Store) CreateAccount(ctx context.Context, username string, kdf vault.KDF, authKey []byte, wrappedKey string) (Account, error) {
	kdfJSON, _ := json.Marshal(kdf)
	a := Account{Username: username, KDF: kdf, AuthHash: Hash(authKey), WrappedKey: wrappedKey}
	err := s.pool.QueryRow(ctx, `INSERT INTO accounts (username, kdf, auth_hash, wrapped_key) VALUES ($1, $2, $3, $4)
		RETURNING id, created_at`, username, kdfJSON, a.AuthHash, wrappedKey).Scan(&a.ID, &a.CreatedAt)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Account{}, ErrDuplicate
	}
	return a, err
}

const accountCols = `id, username, kdf, auth_hash, wrapped_key, revision, created_at`

func scanAccount(row pgx.Row) (Account, error) {
	var a Account
	var kdf []byte
	err := row.Scan(&a.ID, &a.Username, &kdf, &a.AuthHash, &a.WrappedKey, &a.Revision, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	if err == nil {
		err = json.Unmarshal(kdf, &a.KDF)
	}
	return a, err
}

func (s *Store) AccountByName(ctx context.Context, username string) (Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts WHERE lower(username) = lower($1)`, username))
}

func (s *Store) AccountByID(ctx context.Context, id int64) (Account, error) {
	return scanAccount(s.pool.QueryRow(ctx, `SELECT `+accountCols+` FROM accounts WHERE id = $1`, id))
}

// ChangePassword replaces the credentials and ends every other session.
func (s *Store) ChangePassword(ctx context.Context, id int64, kdf vault.KDF, authKey []byte, wrappedKey string, keepToken []byte) error {
	kdfJSON, _ := json.Marshal(kdf)
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE accounts SET kdf = $2, auth_hash = $3, wrapped_key = $4 WHERE id = $1`,
			id, kdfJSON, Hash(authKey), wrappedKey); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `DELETE FROM sessions WHERE account_id = $1 AND token_hash <> $2`, id, Hash(keepToken))
		return err
	})
}

func (s *Store) DeleteAccount(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM accounts WHERE id = $1`, id)
	return err
}

// Sessions.

type Session struct {
	AccountID  int64     `json:"-"`
	ID         string    `json:"id"` // first bytes of the token hash, enough to tell sessions apart
	DeviceName string    `json:"device_name"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	Current    bool      `json:"current"`
}

func (s *Store) CreateSession(ctx context.Context, accountID int64, token []byte, device string, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (token_hash, account_id, device_name, expires_at) VALUES ($1, $2, $3, $4)`,
		Hash(token), accountID, device, time.Now().Add(ttl))
	return err
}

// TouchSession resolves a token and slides its expiry. Expired sessions are removed.
func (s *Store) TouchSession(ctx context.Context, token []byte, ttl time.Duration) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `UPDATE sessions SET last_used_at = now(), expires_at = $2
		WHERE token_hash = $1 AND expires_at > now() RETURNING account_id`, Hash(token), time.Now().Add(ttl)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

func (s *Store) DeleteSession(ctx context.Context, token []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, Hash(token))
	return err
}

func (s *Store) Sessions(ctx context.Context, accountID int64, current []byte) ([]Session, error) {
	rows, err := s.pool.Query(ctx, `SELECT encode(substring(token_hash from 1 for 8), 'hex'), token_hash = $2,
		device_name, created_at, last_used_at FROM sessions WHERE account_id = $1 AND expires_at > now()
		ORDER BY last_used_at DESC`, accountID, Hash(current))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Session, error) {
		var x Session
		err := r.Scan(&x.ID, &x.Current, &x.DeviceName, &x.CreatedAt, &x.LastUsedAt)
		return x, err
	})
}

func (s *Store) DeleteSessionByID(ctx context.Context, accountID int64, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE account_id = $1
		AND encode(substring(token_hash from 1 for 8), 'hex') = $2`, accountID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

func (s *Store) PurgeExpiredSessions(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return err
}

// Items.

type Item struct {
	ID        string    `json:"id"`
	Data      string    `json:"data,omitempty"`
	Deleted   bool      `json:"deleted,omitempty"`
	Revision  int64     `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Changes returns items changed after revision since (all live items when since is 0) and the current revision.
func (s *Store) Changes(ctx context.Context, accountID, since int64) ([]Item, int64, error) {
	var items []Item
	var rev int64
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT revision FROM accounts WHERE id = $1`, accountID).Scan(&rev); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text, COALESCE(data, ''), data IS NULL, revision, updated_at FROM items
			WHERE account_id = $1 AND revision > $2 AND ($2 > 0 OR data IS NOT NULL) ORDER BY revision`, accountID, since)
		if err != nil {
			return err
		}
		items, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Item, error) {
			var it Item
			err := r.Scan(&it.ID, &it.Data, &it.Deleted, &it.Revision, &it.UpdatedAt)
			return it, err
		})
		return err
	})
	return items, rev, err
}

// Write is one change: Data set to upsert, Delete to remove.
type Write struct {
	ID     string `json:"id"`
	Data   string `json:"data,omitempty"`
	Delete bool   `json:"delete,omitempty"`
}

// Apply writes a batch atomically under one new revision and returns it.
func (s *Store) Apply(ctx context.Context, accountID int64, writes []Write) (int64, error) {
	var rev int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE accounts SET revision = revision + 1 WHERE id = $1 RETURNING revision`,
			accountID).Scan(&rev); err != nil {
			return err
		}
		batch := &pgx.Batch{}
		for _, w := range writes {
			var data *string
			if !w.Delete {
				data = &w.Data
			}
			batch.Queue(`INSERT INTO items (account_id, id, data, revision, updated_at) VALUES ($1, $2, $3, $4, now())
				ON CONFLICT (account_id, id) DO UPDATE SET data = EXCLUDED.data, revision = EXCLUDED.revision,
				updated_at = now()`, accountID, w.ID, data, rev)
		}
		return tx.SendBatch(ctx, batch).Close()
	})
	return rev, err
}

func (s *Store) ItemCount(ctx context.Context, accountID int64) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM items WHERE account_id = $1 AND data IS NOT NULL`, accountID).Scan(&n)
	return n, err
}
