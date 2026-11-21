package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Sharing. The server checks membership; it can't read names, items or keys.

// ErrForbidden means the account isn't allowed to do that to the share (not a member, or not its owner).
var ErrForbidden = errors.New("forbidden")

// ErrNoUser means the account to add doesn't exist or has no sharing keys yet.
var ErrNoUser = errors.New("no such user")

// SetShareKeys stores an account's key pair, once: later calls with different keys fail with ErrDuplicate, since
// shares are wrapped for the first public key.
func (s *Store) SetShareKeys(ctx context.Context, accountID int64, publicKey, sealedPrivate string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE accounts SET public_key = $2, sealed_private_key = $3
		WHERE id = $1 AND (public_key IS NULL OR (public_key = $2 AND sealed_private_key = $3))`, accountID, publicKey, sealedPrivate)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrDuplicate
	}
	return err
}

type ShareMember struct {
	Username  string    `json:"username"`
	PublicKey string    `json:"public_key"`
	Owner     bool      `json:"owner,omitempty"`
	AddedAt   time.Time `json:"added_at"`
}

type Share struct {
	ID         string        `json:"id"`
	Owner      string        `json:"owner"`
	Meta       string        `json:"meta"`
	Revision   int64         `json:"revision"`
	WrappedKey string        `json:"wrapped_key"` // for the asking account
	Members    []ShareMember `json:"members"`
}

// Shares lists the shares the account is a member of, with their members.
func (s *Store) Shares(ctx context.Context, accountID int64) ([]Share, error) {
	out := []Share{}
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT sh.id::text, o.username, sh.meta, sh.revision, m.wrapped_key
			FROM share_members m JOIN shares sh ON sh.id = m.share_id JOIN accounts o ON o.id = sh.owner_id
			WHERE m.account_id = $1 ORDER BY sh.created_at, sh.id`, accountID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Share, error) {
			var x Share
			err := r.Scan(&x.ID, &x.Owner, &x.Meta, &x.Revision, &x.WrappedKey)
			x.Members = []ShareMember{}
			return x, err
		})
		if err != nil || len(out) == 0 {
			return err
		}
		byID := map[string]*Share{}
		ids := []string{}
		for i := range out {
			byID[out[i].ID] = &out[i]
			ids = append(ids, out[i].ID)
		}
		rows, err = tx.Query(ctx, `SELECT m.share_id::text, a.username, COALESCE(a.public_key, ''), a.id = sh.owner_id, m.added_at
			FROM share_members m JOIN accounts a ON a.id = m.account_id JOIN shares sh ON sh.id = m.share_id
			WHERE m.share_id = ANY($1::uuid[]) ORDER BY a.id = sh.owner_id DESC, m.added_at, a.username`, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var m ShareMember
			if err := rows.Scan(&id, &m.Username, &m.PublicKey, &m.Owner, &m.AddedAt); err != nil {
				return err
			}
			byID[id].Members = append(byID[id].Members, m)
		}
		return rows.Err()
	})
	return out, err
}

// CreateShare makes a share with its owner as the first member.
func (s *Store) CreateShare(ctx context.Context, ownerID int64, id, meta, wrappedKey string) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO shares (id, owner_id, meta) VALUES ($1, $2, $3)`, id, ownerID, meta); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO share_members (share_id, account_id, wrapped_key) VALUES ($1, $2, $3)`, id, ownerID, wrappedKey)
		return err
	})
	if isDuplicate(err) {
		return ErrDuplicate
	}
	return err
}

// shareRole says whether the account is a member and whether it owns the share. A missing share is ErrNotFound for
// everyone, so non-members learn nothing.
func shareRole(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, shareID string, accountID int64) (member, owner bool, err error) {
	err = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM share_members WHERE share_id = $1 AND account_id = $2),
		owner_id = $2 FROM shares WHERE id = $1`, shareID, accountID).Scan(&member, &owner)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !member) {
		return false, false, ErrNotFound
	}
	return member, owner, err
}

// RenameShare replaces the encrypted name; owner only.
func (s *Store) RenameShare(ctx context.Context, accountID int64, shareID, meta string) error {
	_, owner, err := shareRole(ctx, s.pool, shareID, accountID)
	if err != nil {
		return err
	}
	if !owner {
		return ErrForbidden
	}
	_, err = s.pool.Exec(ctx, `UPDATE shares SET meta = $2 WHERE id = $1`, shareID, meta)
	return err
}

// DeleteShare removes a share and its items (owner), or the account from it (anyone else: leaving).
func (s *Store) DeleteShare(ctx context.Context, accountID int64, shareID string) error {
	_, owner, err := shareRole(ctx, s.pool, shareID, accountID)
	if err != nil {
		return err
	}
	if owner {
		_, err = s.pool.Exec(ctx, `DELETE FROM shares WHERE id = $1`, shareID)
	} else {
		_, err = s.pool.Exec(ctx, `DELETE FROM share_members WHERE share_id = $1 AND account_id = $2`, shareID, accountID)
	}
	return err
}

// AddShareMember adds (or re-keys) a member; owner only. The member must have set up sharing keys.
func (s *Store) AddShareMember(ctx context.Context, accountID int64, shareID, username, wrappedKey string) error {
	_, owner, err := shareRole(ctx, s.pool, shareID, accountID)
	if err != nil {
		return err
	}
	if !owner {
		return ErrForbidden
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO share_members (share_id, account_id, wrapped_key)
		SELECT $1, id, $3 FROM accounts WHERE lower(username) = lower($2) AND public_key IS NOT NULL
		ON CONFLICT (share_id, account_id) DO UPDATE SET wrapped_key = EXCLUDED.wrapped_key`, shareID, username, wrappedKey)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNoUser
	}
	return err
}

// RemoveShareMember takes someone out of a share; the owner can remove anyone but themselves, members only themselves.
func (s *Store) RemoveShareMember(ctx context.Context, accountID int64, shareID, username string) error {
	_, owner, err := shareRole(ctx, s.pool, shareID, accountID)
	if err != nil {
		return err
	}
	var target int64
	var targetOwns bool
	err = s.pool.QueryRow(ctx, `SELECT a.id, a.id = sh.owner_id FROM share_members m JOIN accounts a ON a.id = m.account_id
		JOIN shares sh ON sh.id = m.share_id WHERE m.share_id = $1 AND lower(a.username) = lower($2)`, shareID, username).Scan(&target, &targetOwns)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if targetOwns || (!owner && target != accountID) {
		return ErrForbidden
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM share_members WHERE share_id = $1 AND account_id = $2`, shareID, target)
	return err
}

// ShareChanges is Changes for a share's items; members only.
func (s *Store) ShareChanges(ctx context.Context, accountID int64, shareID string, since int64) ([]Item, int64, error) {
	var items []Item
	var rev int64
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		if _, _, err := shareRole(ctx, tx, shareID, accountID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT revision FROM shares WHERE id = $1`, shareID).Scan(&rev); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id::text, COALESCE(data, ''), data IS NULL, revision, updated_at FROM share_items
			WHERE share_id = $1 AND revision > $2 AND ($2 > 0 OR data IS NOT NULL) ORDER BY revision`, shareID, since)
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

// ApplyShare is Apply for a share's items; any member may write.
func (s *Store) ApplyShare(ctx context.Context, accountID int64, shareID string, writes []Write) (int64, error) {
	var rev int64
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, _, err := shareRole(ctx, tx, shareID, accountID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE shares SET revision = revision + 1 WHERE id = $1 RETURNING revision`, shareID).Scan(&rev); err != nil {
			return err
		}
		batch := &pgx.Batch{}
		for _, w := range writes {
			var data *string
			if !w.Delete {
				data = &w.Data
			}
			batch.Queue(`INSERT INTO share_items (share_id, id, data, revision, updated_at) VALUES ($1, $2, $3, $4, now())
				ON CONFLICT (share_id, id) DO UPDATE SET data = EXCLUDED.data, revision = EXCLUDED.revision,
				updated_at = now(),
				deleted_data = CASE WHEN EXCLUDED.data IS NULL THEN COALESCE(share_items.data, share_items.deleted_data) END,
				deleted_at = CASE WHEN EXCLUDED.data IS NULL THEN
					CASE WHEN share_items.data IS NOT NULL THEN now() ELSE share_items.deleted_at END END`, shareID, w.ID, data, rev)
		}
		return tx.SendBatch(ctx, batch).Close()
	})
	return rev, err
}

// PurgeShareTrash forgets share items deleted more than TrashDays ago.
func (s *Store) PurgeShareTrash(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE share_items SET deleted_data = NULL, deleted_at = NULL
		WHERE deleted_at IS NOT NULL AND deleted_at <= now() - make_interval(days => $1)`, TrashDays)
	return err
}
