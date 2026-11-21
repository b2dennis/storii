package server

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/b2dennis/storii/internal/store"
)

const maxShareMeta = 4 << 10

// validEnvelope checks the shape of an encrypted blob: base64 of version byte, nonce, ciphertext and tag.
func validEnvelope(s string, max int) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(s) <= max && len(b) >= 1+12+16 && b[0] == 1
}

// validWrappedShareKey: "base64(32-byte ephemeral public key).envelope of a 32-byte key".
func validWrappedShareKey(s string) bool {
	eph, env, ok := strings.Cut(s, ".")
	_, keyOK := decodeKey(eph)
	return ok && keyOK && validWrapped(env)
}

// shareErr answers the store's sharing errors.
func (s *Server) shareErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "no such share")
	case errors.Is(err, store.ErrForbidden):
		writeErr(w, http.StatusForbidden, "only the share's owner can do that")
	default:
		s.internal(w, r, err)
	}
}

func shareID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "no such share")
		return "", false
	}
	return id.String(), true
}

// setShareKeys stores the account's sharing key pair, once.
func (s *Server) setShareKeys(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey        string `json:"public_key"`
		SealedPrivateKey string `json:"sealed_private_key"`
	}
	if !decode(w, r, &req) {
		return
	}
	if _, ok := decodeKey(req.PublicKey); !ok || !validWrapped(req.SealedPrivateKey) {
		writeErr(w, http.StatusBadRequest, "public_key or sealed_private_key is malformed")
		return
	}
	err := s.db.SetShareKeys(r.Context(), accountID(r), req.PublicKey, req.SealedPrivateKey)
	if errors.Is(err, store.ErrDuplicate) {
		writeErr(w, http.StatusConflict, "this account already has sharing keys")
		return
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	a, err := s.db.AccountByID(r.Context(), accountID(r))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAccountResp(a))
}

// userKey gives the public key someone needs to add a user to a share. Signed-in users can tell which usernames
// exist this way (prelogin hides that from everyone else).
func (s *Server) userKey(w http.ResponseWriter, r *http.Request) {
	a, err := s.db.AccountByName(r.Context(), r.PathValue("username"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && a.PublicKey == "") {
		writeErr(w, http.StatusNotFound, "no such user, or they haven't opened storii since sharing arrived")
		return
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": a.Username, "public_key": a.PublicKey})
}

func (s *Server) shares(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.Shares(r.Context(), accountID(r))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"shares": list})
}

func (s *Server) createShare(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string `json:"id"`
		Meta       string `json:"meta"`
		WrappedKey string `json:"wrapped_key"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, err := uuid.Parse(req.ID)
	if err != nil || !validEnvelope(req.Meta, maxShareMeta) || !validWrappedShareKey(req.WrappedKey) {
		writeErr(w, http.StatusBadRequest, "id, meta or wrapped_key is malformed")
		return
	}
	a, err := s.db.AccountByID(r.Context(), accountID(r))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if a.PublicKey == "" {
		writeErr(w, http.StatusConflict, "set up sharing keys first")
		return
	}
	err = s.db.CreateShare(r.Context(), a.ID, id.String(), req.Meta, req.WrappedKey)
	if errors.Is(err, store.ErrDuplicate) {
		writeErr(w, http.StatusConflict, "a share with that id exists")
		return
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) renameShare(w http.ResponseWriter, r *http.Request) {
	id, ok := shareID(w, r)
	var req struct {
		Meta string `json:"meta"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if !validEnvelope(req.Meta, maxShareMeta) {
		writeErr(w, http.StatusBadRequest, "meta is malformed")
		return
	}
	if err := s.db.RenameShare(r.Context(), accountID(r), id, req.Meta); err != nil {
		s.shareErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// deleteShare deletes the share with its items (owner) or leaves it (members).
func (s *Server) deleteShare(w http.ResponseWriter, r *http.Request) {
	id, ok := shareID(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteShare(r.Context(), accountID(r), id); err != nil {
		s.shareErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) addShareMember(w http.ResponseWriter, r *http.Request) {
	id, ok := shareID(w, r)
	var req struct {
		WrappedKey string `json:"wrapped_key"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if !validWrappedShareKey(req.WrappedKey) {
		writeErr(w, http.StatusBadRequest, "wrapped_key is malformed")
		return
	}
	err := s.db.AddShareMember(r.Context(), accountID(r), id, r.PathValue("username"), req.WrappedKey)
	if errors.Is(err, store.ErrNoUser) {
		writeErr(w, http.StatusNotFound, "no such user, or they haven't set up sharing yet")
		return
	} else if err != nil {
		s.shareErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) removeShareMember(w http.ResponseWriter, r *http.Request) {
	id, ok := shareID(w, r)
	if !ok {
		return
	}
	if err := s.db.RemoveShareMember(r.Context(), accountID(r), id, r.PathValue("username")); err != nil {
		s.shareErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) shareSync(w http.ResponseWriter, r *http.Request) {
	id, ok := shareID(w, r)
	if !ok {
		return
	}
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	items, rev, err := s.db.ShareChanges(r.Context(), accountID(r), id, max(since, 0))
	if err != nil {
		s.shareErr(w, r, err)
		return
	}
	if items == nil {
		items = []store.Item{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "items": items})
}

func (s *Server) writeShareItems(w http.ResponseWriter, r *http.Request) {
	id, ok := shareID(w, r)
	var req struct {
		Writes []store.Write `json:"writes"`
	}
	if !ok || !decode(w, r, &req) {
		return
	}
	if msg := checkWrites(req.Writes); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	rev, err := s.db.ApplyShare(r.Context(), accountID(r), id, req.Writes)
	if err != nil {
		s.shareErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev})
}
