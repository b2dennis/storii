package client

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/b2dennis/storii/internal/vault"
)

// Backup returns an encrypted backup of every item, sealed with password (see vault.SealBackup).
func (v *Vault) Backup(password string) ([]byte, error) {
	return vault.SealBackup(password, vault.NewKDF(), v.plaintexts(), time.Now(), nil)
}

// plaintexts returns every item's JSON as stored, personal and shared alike.
func (v *Vault) plaintexts() map[string]json.RawMessage {
	items := map[string]json.RawMessage{}
	for id, ri := range v.state.Items {
		if pt, err := vault.DecryptItem(v.key, id, ri.Data); err == nil {
			items[id] = pt
		}
	}
	for sid, sh := range v.state.Shares {
		key := v.shareKeys[sid]
		if key == nil {
			continue
		}
		for id, ri := range sh.Items {
			if pt, err := vault.DecryptShareItem(key, sid, id, ri.Data); err == nil {
				items[id] = pt
			}
		}
	}
	return items
}

// RestoreResult says what RestoreBackup did.
type RestoreResult struct {
	Added   []Entry // items put back, under their ids from the backup
	Skipped int     // items the vault already has (left as they are)
}

// RestoreBackup adds the backup's items that the vault doesn't have, exactly as they were backed up and under the
// same ids (so secrets stay linked to their contexts). Items that are in the vault are left alone. With dryRun
// nothing is written.
func (v *Vault) RestoreBackup(ctx context.Context, password string, file []byte, dryRun bool) (RestoreResult, error) {
	items, err := vault.OpenBackup(password, file)
	if err != nil {
		return RestoreResult{}, err
	}
	var res RestoreResult
	var writes []Write
	plain := map[string]vault.Item{}
	for id, pt := range items {
		if _, ok := v.Items[id]; ok {
			res.Skipped++
			continue
		}
		it, err := vault.UnmarshalItem(pt)
		if _, idErr := uuid.Parse(id); idErr != nil || err != nil || it.Validate() != nil {
			res.Skipped++
			continue
		}
		data, err := vault.EncryptItem(v.key, id, pt)
		if err != nil {
			return res, err
		}
		writes = append(writes, Write{ID: id, Data: data})
		plain[id] = it
		res.Added = append(res.Added, Entry{id, it})
	}
	sort.Slice(res.Added, func(i, j int) bool { return res.Added[i].Name < res.Added[j].Name })
	if dryRun {
		return res, nil
	}
	for chunk := range slices.Chunk(writes, 1000) {
		rev, err := v.state.API().Write(ctx, chunk)
		if err != nil {
			return res, err
		}
		for _, w := range chunk {
			v.state.Items[w.ID] = RemoteItem{ID: w.ID, Data: w.Data, Revision: rev}
			v.Items[w.ID] = plain[w.ID]
		}
	}
	return res, nil
}
