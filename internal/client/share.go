package client

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/b2dennis/storii/internal/vault"
)

// Sharing: shares are separate little vaults whose key is wrapped for each member (docs/CRYPTO.md#sharing). Their
// items show up in Vault.Items next to the personal ones; ItemShare says which share an item lives in.

type ShareMember struct {
	Username  string    `json:"username"`
	PublicKey string    `json:"public_key"`
	Owner     bool      `json:"owner,omitempty"`
	AddedAt   time.Time `json:"added_at"`
}

// ShareState is a share as kept on disk: still encrypted.
type ShareState struct {
	ID         string                `json:"id"`
	Owner      string                `json:"owner"`
	Meta       string                `json:"meta"`
	WrappedKey string                `json:"wrapped_key"`
	Members    []ShareMember         `json:"members"`
	Revision   int64                 `json:"revision"`
	Items      map[string]RemoteItem `json:"items"`
}

// Share is a share's decrypted description.
type Share struct {
	ID      string
	Name    string
	Owner   string
	Members []ShareMember
	Mine    bool // this account owns it
}

// API calls.

type remoteShare struct {
	ShareState
	Revision int64 `json:"revision"`
}

func (a *API) Shares(ctx context.Context) ([]remoteShare, error) {
	var r struct {
		Shares []remoteShare `json:"shares"`
	}
	err := a.call(ctx, http.MethodGet, "/api/v2/shares", nil, &r)
	return r.Shares, err
}

func (a *API) SetShareKeys(ctx context.Context, publicKey, sealedPrivate string) (Account, error) {
	var acct Account
	err := a.call(ctx, http.MethodPut, "/api/v2/account/keys",
		map[string]string{"public_key": publicKey, "sealed_private_key": sealedPrivate}, &acct)
	return acct, err
}

func (a *API) UserKey(ctx context.Context, username string) (string, string, error) {
	var r struct {
		Username  string `json:"username"`
		PublicKey string `json:"public_key"`
	}
	err := a.call(ctx, http.MethodGet, "/api/v2/users/"+url.PathEscape(username)+"/key", nil, &r)
	return r.Username, r.PublicKey, err
}

func sharePath(id string) string { return "/api/v2/shares/" + url.PathEscape(id) }

func (a *API) CreateShare(ctx context.Context, id, meta, wrappedKey string) error {
	return a.call(ctx, http.MethodPost, "/api/v2/shares", map[string]string{"id": id, "meta": meta, "wrapped_key": wrappedKey}, nil)
}

func (a *API) RenameShare(ctx context.Context, id, meta string) error {
	return a.call(ctx, http.MethodPut, sharePath(id), map[string]string{"meta": meta}, nil)
}

func (a *API) DeleteShare(ctx context.Context, id string) error {
	return a.call(ctx, http.MethodDelete, sharePath(id), nil, nil)
}

func (a *API) AddShareMember(ctx context.Context, id, username, wrappedKey string) error {
	return a.call(ctx, http.MethodPut, sharePath(id)+"/members/"+url.PathEscape(username), map[string]string{"wrapped_key": wrappedKey}, nil)
}

func (a *API) RemoveShareMember(ctx context.Context, id, username string) error {
	return a.call(ctx, http.MethodDelete, sharePath(id)+"/members/"+url.PathEscape(username), nil, nil)
}

func (a *API) ShareSync(ctx context.Context, id string, since int64) (int64, []RemoteItem, error) {
	var r struct {
		Revision int64        `json:"revision"`
		Items    []RemoteItem `json:"items"`
	}
	err := a.call(ctx, http.MethodGet, sharePath(id)+"/sync?since="+strconv.FormatInt(since, 10), nil, &r)
	return r.Revision, r.Items, err
}

func (a *API) ShareWrite(ctx context.Context, id string, writes []Write) (int64, error) {
	var r struct {
		Revision int64 `json:"revision"`
	}
	err := a.call(ctx, http.MethodPost, sharePath(id)+"/items", map[string]any{"writes": writes}, &r)
	return r.Revision, err
}

// pullShares follows the shares list: new ones are fetched whole, changed ones from their revision, and shares this
// account left or was removed from are dropped with their items.
func (s *State) pullShares(ctx context.Context) error {
	list, err := s.API().Shares(ctx)
	if err != nil {
		var ae *APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			return nil // a server from before sharing
		}
		return err
	}
	old := s.Shares
	s.Shares = map[string]*ShareState{}
	for _, r := range list {
		sh := old[r.ID]
		if sh == nil || sh.WrappedKey != r.WrappedKey {
			sh = &ShareState{ID: r.ID, Items: map[string]RemoteItem{}}
		}
		sh.Owner, sh.Meta, sh.WrappedKey, sh.Members = r.Owner, r.Meta, r.WrappedKey, r.Members
		if r.Revision != sh.Revision {
			rev, items, err := s.API().ShareSync(ctx, r.ID, sh.Revision)
			if err != nil {
				return err
			}
			if sh.Revision == 0 {
				sh.Items = map[string]RemoteItem{}
			}
			for _, it := range items {
				if it.Deleted {
					delete(sh.Items, it.ID)
				} else {
					sh.Items[it.ID] = it
				}
			}
			sh.Revision = rev
		}
		s.Shares[r.ID] = sh
	}
	return nil
}

// decryptShares opens every share this account can open and adds its items to Items.
func (v *Vault) decryptShares() {
	v.ItemShare, v.Shares, v.shareKeys, v.priv = map[string]string{}, map[string]Share{}, map[string][]byte{}, nil
	if v.state.SealedPrivateKey == "" {
		return
	}
	priv, err := vault.OpenSharePrivateKey(v.key, v.state.SealedPrivateKey)
	if err != nil {
		return
	}
	v.priv = priv
	for sid, sh := range v.state.Shares {
		key, err := vault.UnwrapShareKey(priv, sid, sh.WrappedKey)
		if err != nil {
			continue
		}
		meta, _ := vault.OpenShareMeta(key, sid, sh.Meta)
		v.shareKeys[sid] = key
		v.Shares[sid] = Share{ID: sid, Name: meta.Name, Owner: sh.Owner, Members: sh.Members,
			Mine: strings.EqualFold(sh.Owner, v.state.Username)}
		for id, ri := range sh.Items {
			if _, personal := v.Items[id]; personal {
				continue // the same id in two places: the personal copy wins
			}
			pt, err := vault.DecryptShareItem(key, sid, id, ri.Data)
			if err == nil {
				var it vault.Item
				if it, err = vault.UnmarshalItem(pt); err == nil {
					v.Items[id] = it
					v.ItemShare[id] = sid
					continue
				}
			}
			v.Undecryptable = append(v.Undecryptable, id)
		}
	}
}

// encrypt seals an item for its place: the personal vault (shareID "") or a share.
func (v *Vault) encrypt(shareID, id string, pt []byte) (string, error) {
	if shareID == "" {
		return vault.EncryptItem(v.key, id, pt)
	}
	key := v.shareKeys[shareID]
	if key == nil {
		return "", errors.New("no such share")
	}
	return vault.EncryptShareItem(key, shareID, id, pt, nil)
}

// write sends writes to wherever each item lives (ItemShare, or the personal vault), and updates the local copy.
// plain has the new items for non-deletes.
func (v *Vault) write(ctx context.Context, writes []Write, plain map[string]vault.Item) error {
	return v.writeTo(ctx, writes, plain, func(id string) string { return v.ItemShare[id] })
}

func (v *Vault) writeTo(ctx context.Context, writes []Write, plain map[string]vault.Item, place func(string) string) error {
	groups := map[string][]Write{}
	for _, w := range writes {
		groups[place(w.ID)] = append(groups[place(w.ID)], w)
	}
	for sid, ws := range groups {
		for chunk := range slices.Chunk(ws, 1000) {
			var rev int64
			var err error
			if sid == "" {
				rev, err = v.state.API().Write(ctx, chunk)
			} else {
				rev, err = v.state.API().ShareWrite(ctx, sid, chunk)
			}
			if err != nil {
				return err
			}
			items := v.state.Items
			if sid != "" {
				items = v.state.Shares[sid].Items
			}
			for _, w := range chunk {
				if w.Delete {
					delete(items, w.ID)
					if v.ItemShare[w.ID] == sid {
						delete(v.Items, w.ID)
						delete(v.ItemShare, w.ID)
					}
					continue
				}
				items[w.ID] = RemoteItem{ID: w.ID, Data: w.Data, Revision: rev}
				v.Items[w.ID] = plain[w.ID]
				if sid == "" {
					delete(v.ItemShare, w.ID)
				} else {
					v.ItemShare[w.ID] = sid
				}
			}
		}
	}
	return nil
}

// SetupSharing creates this account's sharing key pair if it has none yet. Every client does this after unlocking,
// so others can add the account to shares.
func (v *Vault) SetupSharing(ctx context.Context) error {
	if v.state.PublicKey != "" {
		return nil
	}
	priv, pub := vault.NewShareKeyPair()
	sealed, err := vault.SealSharePrivateKey(v.key, priv)
	if err != nil {
		return err
	}
	acct, err := v.state.API().SetShareKeys(ctx, base64.StdEncoding.EncodeToString(pub), sealed)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusConflict {
		// Another device got there first: use its keys.
		acct, err = v.state.API().Account(ctx)
	}
	if err != nil {
		return err
	}
	v.state.PublicKey, v.state.SealedPrivateKey = acct.PublicKey, acct.SealedPrivateKey
	v.decryptAll()
	return nil
}

// Fingerprint is this account's key fingerprint, for others to compare when they add it to a share.
func (v *Vault) Fingerprint() string {
	pub, err := base64.StdEncoding.DecodeString(v.state.PublicKey)
	if err != nil || len(pub) == 0 {
		return ""
	}
	return vault.Fingerprint(pub)
}

// ShareList returns the shares sorted by name.
func (v *Vault) ShareList() []Share {
	out := make([]Share, 0, len(v.Shares))
	for _, s := range v.Shares {
		out = append(out, s)
	}
	slices.SortFunc(out, func(a, b Share) int { return strings.Compare(strings.ToLower(a.Name)+a.ID, strings.ToLower(b.Name)+b.ID) })
	return out
}

// FindShare resolves a share by name or id prefix.
func (v *Vault) FindShare(query string) (Share, error) {
	var hits []Share
	for _, s := range v.ShareList() {
		if strings.EqualFold(s.Name, query) || s.ID == query {
			return s, nil
		}
		if len(query) >= 4 && strings.HasPrefix(s.ID, query) || strings.Contains(strings.ToLower(s.Name), strings.ToLower(query)) {
			hits = append(hits, s)
		}
	}
	if len(hits) == 1 {
		return hits[0], nil
	}
	if len(hits) > 1 {
		return Share{}, errors.New("ambiguous share name: " + query)
	}
	return Share{}, errors.New("no share called " + query)
}

func (v *Vault) needSharing(ctx context.Context) error {
	if err := v.SetupSharing(ctx); err != nil {
		return err
	}
	if v.priv == nil {
		return errors.New("the sharing key doesn't open with this vault key")
	}
	return nil
}

// CreateShare makes a share owned by this account.
func (v *Vault) CreateShare(ctx context.Context, name string) (Share, error) {
	if err := v.needSharing(ctx); err != nil {
		return Share{}, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Share{}, errors.New("a share needs a name")
	}
	id := uuid.NewString()
	key := vault.NewShareKey()
	pub, _ := vault.PublicKeyOf(v.priv)
	wrapped, err := vault.WrapShareKey(pub, id, key, nil, nil)
	if err != nil {
		return Share{}, err
	}
	meta, err := vault.SealShareMeta(key, id, vault.ShareMeta{Name: name}, nil)
	if err != nil {
		return Share{}, err
	}
	if err := v.state.API().CreateShare(ctx, id, meta, wrapped); err != nil {
		return Share{}, err
	}
	if v.state.Shares == nil {
		v.state.Shares = map[string]*ShareState{}
	}
	me := []ShareMember{{Username: v.state.Username, PublicKey: v.state.PublicKey, Owner: true, AddedAt: time.Now()}}
	v.state.Shares[id] = &ShareState{ID: id, Owner: v.state.Username, Meta: meta, WrappedKey: wrapped, Members: me, Items: map[string]RemoteItem{}}
	v.decryptAll()
	return v.Shares[id], nil
}

// RenameShare changes a share's name; owner only.
func (v *Vault) RenameShare(ctx context.Context, shareID, name string) error {
	key := v.shareKeys[shareID]
	if key == nil {
		return errors.New("no such share")
	}
	meta, err := vault.SealShareMeta(key, shareID, vault.ShareMeta{Name: strings.TrimSpace(name)}, nil)
	if err != nil {
		return err
	}
	if err := v.state.API().RenameShare(ctx, shareID, meta); err != nil {
		return err
	}
	v.state.Shares[shareID].Meta = meta
	v.decryptAll()
	return nil
}

// MemberKey looks up someone's public key and its fingerprint, to compare with them before adding them.
func (v *Vault) MemberKey(ctx context.Context, username string) (name, publicKey, fingerprint string, err error) {
	name, publicKey, err = v.state.API().UserKey(ctx, username)
	if err != nil {
		return "", "", "", err
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(pub) != 32 {
		return "", "", "", errors.New("the server sent a malformed key")
	}
	return name, publicKey, vault.Fingerprint(pub), nil
}

// AddMember gives username (whose publicKey came from MemberKey) the share's key; owner only.
func (v *Vault) AddMember(ctx context.Context, shareID, username, publicKey string) error {
	key := v.shareKeys[shareID]
	if key == nil {
		return errors.New("no such share")
	}
	pub, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return err
	}
	wrapped, err := vault.WrapShareKey(pub, shareID, key, nil, nil)
	if err != nil {
		return err
	}
	if err := v.state.API().AddShareMember(ctx, shareID, username, wrapped); err != nil {
		return err
	}
	return v.Refresh(ctx)
}

// RemoveMember takes someone out of a share (the owner anyone, members themselves). They keep whatever they copied
// before; change those passwords if that matters.
func (v *Vault) RemoveMember(ctx context.Context, shareID, username string) error {
	if err := v.state.API().RemoveShareMember(ctx, shareID, username); err != nil {
		return err
	}
	return v.Refresh(ctx)
}

// DeleteShare deletes a share with its items (owner) or leaves it (members).
func (v *Vault) DeleteShare(ctx context.Context, shareID string) error {
	if err := v.state.API().DeleteShare(ctx, shareID); err != nil {
		return err
	}
	delete(v.state.Shares, shareID)
	v.decryptAll()
	return nil
}

// Move puts items into a share (or back into the personal vault with shareID ""), under the same ids. Contexts a
// moved secret links go along when nothing staying behind uses them; otherwise the secret gets a copy of the context
// in its new place.
func (v *Vault) Move(ctx context.Context, ids []string, shareID string) error {
	if shareID != "" && v.shareKeys[shareID] == nil {
		return errors.New("no such share")
	}
	moving := map[string]bool{}
	for _, id := range ids {
		if _, ok := v.Items[id]; !ok {
			return errors.New("no such item " + id)
		}
		if v.ItemShare[id] != shareID {
			moving[id] = true
		}
	}
	// Contexts of moved secrets: move them too when only moving secrets use them, else copy.
	items := map[string]vault.Item{}
	for id := range moving {
		items[id] = v.Items[id]
	}
	for id := range moving {
		it := items[id]
		if it.Kind != vault.KindSecret {
			continue
		}
		for i, c := range it.Contexts {
			if moving[c] || v.ItemShare[c] == shareID {
				continue
			}
			ctxItem, ok := v.Items[c]
			if !ok {
				continue
			}
			usedElsewhere := false
			for sid, s := range v.Items {
				if !moving[sid] && slices.Contains(s.Contexts, c) {
					usedElsewhere = true
					break
				}
			}
			if !usedElsewhere {
				moving[c] = true
				items[c] = ctxItem
				continue
			}
			copyID := uuid.NewString()
			ctxItem.CreatedAt = time.Time{}
			items[copyID] = ctxItem
			moving[copyID] = true
			it.Contexts = slices.Clone(it.Contexts)
			it.Contexts[i] = copyID
		}
		items[id] = it
	}
	if len(items) == 0 {
		return nil
	}
	now := time.Now().UTC().Truncate(time.Second)
	var puts, deletes []Write
	from := map[string]string{}
	plain := map[string]vault.Item{}
	for id, it := range items {
		if it.CreatedAt.IsZero() {
			it.CreatedAt = now
		}
		pt, err := it.Marshal()
		if err != nil {
			return err
		}
		data, err := v.encrypt(shareID, id, pt)
		if err != nil {
			return err
		}
		puts = append(puts, Write{ID: id, Data: data})
		plain[id] = it
		if _, existed := v.Items[id]; existed {
			from[id] = v.ItemShare[id]
			deletes = append(deletes, Write{ID: id, Delete: true})
		}
	}
	// Write to the new place first, so a failure halfway leaves a copy rather than nothing.
	if err := v.writeTo(ctx, puts, plain, func(string) string { return shareID }); err != nil {
		return err
	}
	var personalGone []string
	for _, d := range deletes {
		if from[d.ID] == "" {
			personalGone = append(personalGone, d.ID)
		}
	}
	if err := v.removeFrom(ctx, deletes, from); err != nil {
		return err
	}
	// A moved item isn't deleted: keep it out of the personal trash, where restoring it would duplicate it.
	if len(personalGone) > 0 {
		_ = v.state.API().EmptyTrash(ctx, personalGone)
	}
	return nil
}

// removeFrom deletes items from their old places without touching the decrypted copies at their new place.
func (v *Vault) removeFrom(ctx context.Context, deletes []Write, from map[string]string) error {
	groups := map[string][]Write{}
	for _, d := range deletes {
		groups[from[d.ID]] = append(groups[from[d.ID]], d)
	}
	for sid, ws := range groups {
		for chunk := range slices.Chunk(ws, 1000) {
			var err error
			if sid == "" {
				_, err = v.state.API().Write(ctx, chunk)
			} else {
				_, err = v.state.API().ShareWrite(ctx, sid, chunk)
			}
			if err != nil {
				return err
			}
			for _, w := range chunk {
				if sid == "" {
					delete(v.state.Items, w.ID)
				} else if sh := v.state.Shares[sid]; sh != nil {
					delete(sh.Items, w.ID)
				}
			}
		}
	}
	return nil
}
