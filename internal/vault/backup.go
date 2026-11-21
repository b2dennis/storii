package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// An encrypted backup: every item's plaintext, keyed by id, sealed with a key derived from a backup password the same
// way as the login keys (Argon2id + HKDF "storii wrap"), with its own AAD. It doesn't need the server or the account.
//
//	{"storii_backup": 1, "exported_at": "...", "kdf": {...}, "data": seal(key, {"items": {id: item}}, "storii:backup")}
const (
	BackupVersion = 1
	aadBackup     = "storii:backup"
)

type Backup struct {
	Version    int    `json:"storii_backup"`
	ExportedAt string `json:"exported_at"`
	KDF        KDF    `json:"kdf"`
	Data       string `json:"data"`
}

type backupContents struct {
	Items map[string]json.RawMessage `json:"items"`
}

var ErrBackupPassword = errors.New("wrong backup password, or the file is damaged")

// SealBackup encrypts items (id → item JSON) with password. A nil nonce picks a random one (tests pass one in).
func SealBackup(password string, kdf KDF, items map[string]json.RawMessage, now time.Time, nonce []byte) ([]byte, error) {
	keys, err := DeriveKeys(password, kdf)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(backupContents{Items: items})
	if err != nil {
		return nil, err
	}
	data, err := seal(keys.Wrap, plain, aadBackup, nonce)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(Backup{BackupVersion, now.UTC().Format(time.RFC3339), kdf, data}, "", "  ")
}

// IsBackup tells a storii backup from other JSON files (imports from other password managers).
func IsBackup(file []byte) bool {
	var b struct {
		Version int `json:"storii_backup"`
	}
	return json.Unmarshal(file, &b) == nil && b.Version > 0
}

// OpenBackup decrypts a backup file, returning id → item JSON.
func OpenBackup(password string, file []byte) (map[string]json.RawMessage, error) {
	var b Backup
	if err := json.Unmarshal(file, &b); err != nil || b.Version == 0 {
		return nil, errors.New("not a storii backup")
	}
	if b.Version != BackupVersion {
		return nil, fmt.Errorf("storii backup version %d needs a newer storii", b.Version)
	}
	keys, err := DeriveKeys(password, b.KDF)
	if err != nil {
		return nil, err
	}
	plain, err := open(keys.Wrap, b.Data, aadBackup)
	if err != nil {
		return nil, ErrBackupPassword
	}
	var c backupContents
	if err := json.Unmarshal(plain, &c); err != nil {
		return nil, fmt.Errorf("damaged backup: %w", err)
	}
	return c.Items, nil
}
