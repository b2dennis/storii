package client

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/b2dennis/storii/internal/vault"
)

// State is what a client keeps on disk: the session token and the still-encrypted vault. Nothing in it can be
// decrypted without the master password.
type State struct {
	Server     string                `json:"server"`
	Username   string                `json:"username"`
	Token      string                `json:"token"`
	KDF        vault.KDF             `json:"kdf"`
	WrappedKey string                `json:"wrapped_key"`
	Revision   int64                 `json:"revision"`
	Items      map[string]RemoteItem `json:"items"`
}

func LoadState(path string) (*State, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if s.Items == nil {
		s.Items = map[string]RemoteItem{}
	}
	return &s, nil
}

func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(s, "", " ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *State) API() *API { return NewAPI(s.Server, s.Token) }

// Pull fetches changes since the last sync.
func (s *State) Pull(ctx context.Context) error {
	acct, err := s.API().Account(ctx)
	if err != nil {
		return err
	}
	// Another device changed the master password: the wrapped key and KDF follow.
	s.KDF, s.WrappedKey = acct.KDF, acct.WrappedKey
	rev, items, err := s.API().Sync(ctx, s.Revision)
	if err != nil {
		return err
	}
	// since=0 is a full snapshot without tombstones: replace, or deletions made elsewhere would never arrive.
	if s.Revision == 0 {
		s.Items = map[string]RemoteItem{}
	}
	for _, it := range items {
		if it.Deleted {
			delete(s.Items, it.ID)
		} else {
			s.Items[it.ID] = it
		}
	}
	s.Revision = rev
	return nil
}

// Login creates a session and downloads the vault. It returns the unlocked vault.
func Login(ctx context.Context, server, username, password, device string) (*State, *Vault, error) {
	api := NewAPI(server, "")
	if err := api.Ping(ctx); err != nil {
		return nil, nil, err
	}
	kdf, err := api.Prelogin(ctx, username)
	if err != nil {
		return nil, nil, err
	}
	keys, err := vault.DeriveKeys(password, kdf)
	if err != nil {
		return nil, nil, err
	}
	resp, err := api.Login(ctx, username, keys.AuthKey(), device)
	if err != nil {
		return nil, nil, err
	}
	st := &State{Server: api.BaseURL, Username: resp.Account.Username, Token: resp.Token, KDF: resp.Account.KDF,
		WrappedKey: resp.Account.WrappedKey, Items: map[string]RemoteItem{}}
	if err := st.Pull(ctx); err != nil {
		return nil, nil, err
	}
	v, err := st.unlockWith(keys)
	return st, v, err
}

// Register creates an account with a fresh vault key.
func Register(ctx context.Context, server, username, password, device string) (*State, *Vault, error) {
	api := NewAPI(server, "")
	if err := api.Ping(ctx); err != nil {
		return nil, nil, err
	}
	kdf := vault.NewKDF()
	keys, err := vault.DeriveKeys(password, kdf)
	if err != nil {
		return nil, nil, err
	}
	vk := vault.NewVaultKey()
	wrapped, err := vault.WrapVaultKey(keys.Wrap, vk)
	if err != nil {
		return nil, nil, err
	}
	resp, err := api.Register(ctx, username, kdf, keys.AuthKey(), wrapped, device)
	if err != nil {
		return nil, nil, err
	}
	st := &State{Server: api.BaseURL, Username: resp.Account.Username, Token: resp.Token, KDF: kdf,
		WrappedKey: wrapped, Items: map[string]RemoteItem{}}
	return st, &Vault{state: st, key: vk, keys: keys, Items: map[string]vault.Item{}}, nil
}

// Vault is the decrypted view of a State.
type Vault struct {
	state *State
	key   []byte
	keys  vault.Keys
	Items map[string]vault.Item
	// Undecryptable holds ids whose data didn't decrypt (written by a broken client, or tampered with).
	Undecryptable []string
}

// Unlock derives the keys from the master password and decrypts the local copy.
func (s *State) Unlock(password string) (*Vault, error) {
	keys, err := vault.DeriveKeys(password, s.KDF)
	if err != nil {
		return nil, err
	}
	return s.unlockWith(keys)
}

func (s *State) unlockWith(keys vault.Keys) (*Vault, error) {
	vk, err := vault.UnwrapVaultKey(keys.Wrap, s.WrappedKey)
	if err != nil {
		return nil, errors.New("wrong master password")
	}
	v := &Vault{state: s, key: vk, keys: keys}
	v.decryptAll()
	return v, nil
}

func (v *Vault) decryptAll() {
	v.Items = map[string]vault.Item{}
	v.Undecryptable = nil
	for id, ri := range v.state.Items {
		pt, err := vault.DecryptItem(v.key, id, ri.Data)
		if err == nil {
			var it vault.Item
			if it, err = vault.UnmarshalItem(pt); err == nil {
				v.Items[id] = it
				continue
			}
		}
		v.Undecryptable = append(v.Undecryptable, id)
	}
}

// Refresh pulls from the server and re-decrypts.
func (v *Vault) Refresh(ctx context.Context) error {
	if err := v.state.Pull(ctx); err != nil {
		return err
	}
	vk, err := vault.UnwrapVaultKey(v.keys.Wrap, v.state.WrappedKey)
	if err == nil {
		v.key = vk
	} else if v.keys.Wrap != nil {
		return errors.New("the master password was changed on another device; unlock again")
	}
	v.decryptAll()
	return nil
}

func (v *Vault) AuthKey() string { return v.keys.AuthKey() }

// Put encrypts and uploads items (new ones get an id when theirs is empty) and returns their ids.
func (v *Vault) Put(ctx context.Context, items map[string]vault.Item) ([]string, error) {
	now := time.Now().UTC().Truncate(time.Second)
	writes := make([]Write, 0, len(items))
	ids := make([]string, 0, len(items))
	plain := map[string]vault.Item{}
	for id, it := range items {
		if id == "" || strings.HasPrefix(id, "new:") {
			id = uuid.NewString()
		}
		if it.CreatedAt.IsZero() {
			it.CreatedAt = now
		}
		it.UpdatedAt = now
		if err := it.Validate(); err != nil {
			return nil, err
		}
		pt, err := it.Marshal()
		if err != nil {
			return nil, err
		}
		data, err := vault.EncryptItem(v.key, id, pt)
		if err != nil {
			return nil, err
		}
		writes = append(writes, Write{ID: id, Data: data})
		ids = append(ids, id)
		plain[id] = it
	}
	for chunk := range slices.Chunk(writes, 1000) {
		rev, err := v.state.API().Write(ctx, chunk)
		if err != nil {
			return nil, err
		}
		for _, w := range chunk {
			v.state.Items[w.ID] = RemoteItem{ID: w.ID, Data: w.Data, Revision: rev}
			v.Items[w.ID] = plain[w.ID]
		}
	}
	return ids, nil
}

// PutOne is Put for one item; pass "" as id for a new one.
func (v *Vault) PutOne(ctx context.Context, id string, it vault.Item) (string, error) {
	ids, err := v.Put(ctx, map[string]vault.Item{id: it})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// Delete removes items. Deleting a context also unlinks it from its secrets.
func (v *Vault) Delete(ctx context.Context, ids ...string) error {
	changed := map[string]vault.Item{}
	for _, id := range ids {
		if v.Items[id].Kind != vault.KindContext {
			continue
		}
		for sid, s := range v.Items {
			if slices.Contains(s.Contexts, id) && !slices.Contains(ids, sid) {
				s.Contexts = slices.DeleteFunc(slices.Clone(s.Contexts), func(c string) bool { return c == id })
				changed[sid] = s
			}
		}
	}
	if len(changed) > 0 {
		if _, err := v.Put(ctx, changed); err != nil {
			return err
		}
	}
	writes := make([]Write, len(ids))
	for i, id := range ids {
		writes[i] = Write{ID: id, Delete: true}
	}
	if _, err := v.state.API().Write(ctx, writes); err != nil {
		return err
	}
	for _, id := range ids {
		delete(v.state.Items, id)
		delete(v.Items, id)
	}
	return nil
}

// Entry is an item with its id.
type Entry struct {
	ID string
	vault.Item
}

// List returns items of a kind sorted by name.
func (v *Vault) List(kind string) []Entry {
	var out []Entry
	for id, it := range v.Items {
		if it.Kind == kind {
			out = append(out, Entry{id, it})
		}
	}
	slices.SortFunc(out, func(a, b Entry) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)), cmp.Compare(a.ID, b.ID))
	})
	return out
}

// Find resolves a name, id or id prefix to one item of a kind, optionally only of some secret types.
func (v *Vault) Find(kind, query string, types ...string) (Entry, error) {
	var exact, partial []Entry
	q := strings.ToLower(query)
	for _, e := range v.List(kind) {
		if len(types) > 0 && !slices.Contains(types, e.Type) {
			continue
		}
		switch {
		case e.ID == query || strings.ToLower(e.Name) == q:
			exact = append(exact, e)
		case strings.HasPrefix(e.ID, query) || strings.Contains(strings.ToLower(e.Name), q):
			partial = append(partial, e)
		}
	}
	for _, set := range [][]Entry{exact, partial} {
		if len(set) == 1 {
			return set[0], nil
		}
		if len(set) > 1 {
			names := make([]string, len(set))
			for i, e := range set {
				names[i] = e.Name + " (" + e.ID[:8] + ")"
			}
			return Entry{}, errors.New("ambiguous, matches: " + strings.Join(names, ", "))
		}
	}
	return Entry{}, errors.New("nothing matches " + query)
}

// ForSite returns the secrets linked to contexts matching a host or Android package.
func (v *Vault) ForSite(host, androidPackage string) []Entry {
	ctxs := map[string]bool{}
	for id, it := range v.Items {
		if it.MatchesContext(host, androidPackage) {
			ctxs[id] = true
		}
	}
	var out []Entry
	for _, e := range v.List(vault.KindSecret) {
		for _, c := range e.Contexts {
			if ctxs[c] {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// ChangePassword re-wraps the vault key under a new master password. Other sessions are signed out.
func (v *Vault) ChangePassword(ctx context.Context, newPassword string) error {
	kdf := vault.NewKDF()
	keys, err := vault.DeriveKeys(newPassword, kdf)
	if err != nil {
		return err
	}
	wrapped, err := vault.WrapVaultKey(keys.Wrap, v.key)
	if err != nil {
		return err
	}
	acct, err := v.state.API().ChangePassword(ctx, v.keys.AuthKey(), kdf, keys.AuthKey(), wrapped)
	if err != nil {
		return err
	}
	v.state.KDF, v.state.WrappedKey, v.keys = acct.KDF, acct.WrappedKey, keys
	return nil
}

// Clone copies the state, so a background sync can pull into the copy while the original stays in use.
func (s *State) Clone() *State {
	c := *s
	c.Items = make(map[string]RemoteItem, len(s.Items))
	for k, v := range s.Items {
		c.Items[k] = v
	}
	return &c
}

// Reopen decrypts another state (usually a synced Clone) with this vault's keys, without the master password.
func (v *Vault) Reopen(s *State) (*Vault, error) {
	nv, err := s.unlockWith(v.keys)
	if err != nil {
		return nil, errors.New("the master password was changed on another device; unlock again")
	}
	return nv, nil
}

// State returns the state this vault decrypts.
func (v *Vault) State() *State { return v.state }
