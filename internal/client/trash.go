package client

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// TrashItem is a deleted item's last ciphertext, as GET /api/v2/trash returns it.
type TrashItem struct {
	ID        string    `json:"id"`
	Data      string    `json:"data"`
	DeletedAt time.Time `json:"deleted_at"`
}

// Trash lists deleted items that can still be restored, newest first, and for how many days they're kept.
func (a *API) Trash(ctx context.Context) ([]TrashItem, int, error) {
	var r struct {
		Items []TrashItem `json:"items"`
		Days  int         `json:"days"`
	}
	err := a.call(ctx, http.MethodGet, "/api/v2/trash", nil, &r)
	return r.Items, r.Days, err
}

// EmptyTrash forgets deleted items for good: the given ids, or all of them.
func (a *API) EmptyTrash(ctx context.Context, ids []string) error {
	if ids == nil {
		ids = []string{}
	}
	return a.call(ctx, http.MethodDelete, "/api/v2/trash", map[string]any{"ids": ids}, nil)
}

// Deleted is a decrypted trash entry.
type Deleted struct {
	Entry
	DeletedAt time.Time
	data      string
}

// Trash lists the deleted items this vault key can read, newest first.
func (v *Vault) Trash(ctx context.Context) ([]Deleted, int, error) {
	items, days, err := v.state.API().Trash(ctx)
	if err != nil {
		return nil, 0, err
	}
	var out []Deleted
	for _, t := range items {
		pt, err := vault.DecryptItem(v.key, t.ID, t.Data)
		if err != nil {
			continue
		}
		it, err := vault.UnmarshalItem(pt)
		if err != nil {
			continue
		}
		out = append(out, Deleted{Entry: Entry{t.ID, it}, DeletedAt: t.DeletedAt, data: t.Data})
	}
	return out, days, nil
}

// Restore puts deleted items back exactly as they were, under their old ids.
func (v *Vault) Restore(ctx context.Context, items ...Deleted) error {
	for chunk := range slices.Chunk(items, 1000) {
		writes := make([]Write, len(chunk))
		for i, d := range chunk {
			writes[i] = Write{ID: d.ID, Data: d.data}
		}
		rev, err := v.state.API().Write(ctx, writes)
		if err != nil {
			return err
		}
		for _, d := range chunk {
			v.state.Items[d.ID] = RemoteItem{ID: d.ID, Data: d.data, Revision: rev}
			v.Items[d.ID] = d.Item
		}
	}
	return nil
}

// EmptyTrash forgets deleted items for good: the given ids, or all of them when ids is empty.
func (v *Vault) EmptyTrash(ctx context.Context, ids []string) error {
	return v.state.API().EmptyTrash(ctx, ids)
}
