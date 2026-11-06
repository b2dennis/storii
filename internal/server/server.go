// Package server is the storii v2 HTTP API. It never sees a master password or a decryption key: it stores the
// client's KDF parameters, a hash of the auth key, the wrapped vault key and opaque encrypted items.
package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/b2dennis/storii/internal/store"
	"github.com/b2dennis/storii/internal/vault"
)

type Config struct {
	Secret       []byte        // for the fake KDF salts of unknown usernames
	SessionTTL   time.Duration // sliding
	Registration bool
	TrustProxy   bool // take the client IP from X-Forwarded-For
	AuthRate     rate.Limit
	AuthBurst    int
}

const (
	maxItemBytes  = 256 << 10
	maxBatch      = 2000
	maxBodyBytes  = 32 << 20
	maxDeviceName = 100
)

type Server struct {
	db  *store.Store
	cfg Config
	log *slog.Logger

	mu       sync.Mutex
	limiters map[string]*limiter
}

type limiter struct {
	*rate.Limiter
	seen time.Time
}

func New(db *store.Store, cfg Config, log *slog.Logger) http.Handler {
	s := &Server{db: db, cfg: cfg, log: log, limiters: map[string]*limiter{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /api/v2/ping", s.healthz)
	mux.HandleFunc("POST /api/v2/prelogin", s.limited(s.prelogin))
	mux.HandleFunc("POST /api/v2/register", s.limited(s.register))
	mux.HandleFunc("POST /api/v2/login", s.limited(s.login))
	mux.HandleFunc("POST /api/v2/logout", s.authed(s.logout))
	mux.HandleFunc("GET /api/v2/account", s.authed(s.account))
	mux.HandleFunc("PUT /api/v2/account/password", s.authed(s.changePassword))
	mux.HandleFunc("DELETE /api/v2/account", s.authed(s.deleteAccount))
	mux.HandleFunc("GET /api/v2/sessions", s.authed(s.sessions))
	mux.HandleFunc("DELETE /api/v2/sessions/{id}", s.authed(s.deleteSession))
	mux.HandleFunc("GET /api/v2/sync", s.authed(s.sync))
	mux.HandleFunc("POST /api/v2/items", s.authed(s.writeItems))
	go s.janitor()
	return s.cors(mux)
}

// cors allows any origin: requests carry a bearer token, never cookies. The browser extension doesn't need it, a
// web client would.
func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) janitor() {
	for range time.Tick(time.Hour) {
		if err := s.db.PurgeExpiredSessions(context.Background()); err != nil {
			s.log.Warn("purge sessions", "err", err)
		}
		s.mu.Lock()
		for ip, l := range s.limiters {
			if time.Since(l.seen) > 10*time.Minute {
				delete(s.limiters, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Ping(r.Context()); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "api": "v2"})
}

// Helpers.

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.TrustProxy {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			ip, _, _ := strings.Cut(f, ",")
			return strings.TrimSpace(ip)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := s.clientIP(r)
		s.mu.Lock()
		l, ok := s.limiters[ip]
		if !ok {
			l = &limiter{Limiter: rate.NewLimiter(s.cfg.AuthRate, s.cfg.AuthBurst)}
			s.limiters[ip] = l
		}
		l.seen = time.Now()
		allowed := l.Allow()
		s.mu.Unlock()
		if !allowed {
			w.Header().Set("Retry-After", "10")
			writeErr(w, http.StatusTooManyRequests, "too many attempts, slow down")
			return
		}
		next(w, r)
	}
}

type ctxKey int

const (
	ctxAccount ctxKey = iota
	ctxToken
)

func (s *Server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := base64.RawURLEncoding.DecodeString(raw)
		if !ok || err != nil || len(token) != 32 {
			writeErr(w, http.StatusUnauthorized, "missing or malformed token")
			return
		}
		id, err := s.db.TouchSession(r.Context(), token, s.cfg.SessionTTL)
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusUnauthorized, "session expired or revoked, log in again")
			return
		} else if err != nil {
			s.internal(w, r, err)
			return
		}
		ctx := context.WithValue(r.Context(), ctxAccount, id)
		next(w, r.WithContext(context.WithValue(ctx, ctxToken, token)))
	}
}

func accountID(r *http.Request) int64 { return r.Context().Value(ctxAccount).(int64) }
func token(r *http.Request) []byte    { return r.Context().Value(ctxToken).([]byte) }

func (s *Server) newSession(ctx context.Context, accountID int64, device string) (string, error) {
	tok := make([]byte, 32)
	rand.Read(tok)
	if len(device) > maxDeviceName {
		device = device[:maxDeviceName]
	}
	if err := s.db.CreateSession(ctx, accountID, tok, device, s.cfg.SessionTTL); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tok), nil
}

var usernameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.@-]{2,63}$`)

func decodeKey(s string) ([]byte, bool) {
	b, err := base64.StdEncoding.DecodeString(s)
	return b, err == nil && len(b) == 32
}

// validWrapped checks the shape of a wrapped vault key: version byte, nonce, 32-byte key, tag.
func validWrapped(s string) bool {
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 1+12+32+16 && b[0] == 1
}

// Handlers.

type accountResp struct {
	Username   string    `json:"username"`
	KDF        vault.KDF `json:"kdf"`
	WrappedKey string    `json:"wrapped_key"`
	Revision   int64     `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
}

func toAccountResp(a store.Account) accountResp {
	return accountResp{a.Username, a.KDF, a.WrappedKey, a.Revision, a.CreatedAt}
}

type sessionResp struct {
	Token   string      `json:"token"`
	Account accountResp `json:"account"`
}

func (s *Server) prelogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
	}
	if !decode(w, r, &req) {
		return
	}
	a, err := s.db.AccountByName(r.Context(), req.Username)
	if errors.Is(err, store.ErrNotFound) {
		// Answer the same way for unknown users, with a salt that is stable per name, so the endpoint doesn't
		// reveal which usernames exist.
		mac := hmac.New(sha256.New, s.cfg.Secret)
		mac.Write([]byte(strings.ToLower(req.Username)))
		kdf := vault.NewKDF()
		kdf.Salt = base64.StdEncoding.EncodeToString(mac.Sum(nil)[:16])
		writeJSON(w, http.StatusOK, map[string]any{"kdf": kdf})
		return
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"kdf": a.KDF})
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Registration {
		writeErr(w, http.StatusForbidden, "registration is closed on this server")
		return
	}
	var req struct {
		Username   string    `json:"username"`
		KDF        vault.KDF `json:"kdf"`
		AuthKey    string    `json:"auth_key"`
		WrappedKey string    `json:"wrapped_key"`
		DeviceName string    `json:"device_name"`
	}
	if !decode(w, r, &req) {
		return
	}
	authKey, ok := decodeKey(req.AuthKey)
	switch {
	case !usernameRe.MatchString(req.Username):
		writeErr(w, http.StatusBadRequest, "username must be 3-64 letters, digits or _.@- and start with a letter")
		return
	case req.KDF.Validate() != nil:
		writeErr(w, http.StatusBadRequest, req.KDF.Validate().Error())
		return
	case !ok:
		writeErr(w, http.StatusBadRequest, "auth_key must be 32 bytes of base64")
		return
	case !validWrapped(req.WrappedKey):
		writeErr(w, http.StatusBadRequest, "wrapped_key is malformed")
		return
	}
	a, err := s.db.CreateAccount(r.Context(), req.Username, req.KDF, authKey, req.WrappedKey)
	if errors.Is(err, store.ErrDuplicate) {
		writeErr(w, http.StatusConflict, "username is taken")
		return
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	tok, err := s.newSession(r.Context(), a.ID, req.DeviceName)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.log.Info("account created", "username", a.Username)
	writeJSON(w, http.StatusCreated, sessionResp{tok, toAccountResp(a)})
}

var dummyHash = make([]byte, 32)

func (s *Server) checkAuthKey(a store.Account, found bool, authKeyB64 string) bool {
	key, ok := decodeKey(authKeyB64)
	want := dummyHash
	if found {
		want = a.AuthHash
	}
	match := subtle.ConstantTimeCompare(store.Hash(key), want) == 1
	return ok && found && match
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		AuthKey    string `json:"auth_key"`
		DeviceName string `json:"device_name"`
	}
	if !decode(w, r, &req) {
		return
	}
	a, err := s.db.AccountByName(r.Context(), req.Username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	if !s.checkAuthKey(a, err == nil, req.AuthKey) {
		writeErr(w, http.StatusUnauthorized, "wrong username or master password")
		return
	}
	tok, err := s.newSession(r.Context(), a.ID, req.DeviceName)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResp{tok, toAccountResp(a)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := s.db.DeleteSession(r.Context(), token(r)); err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) account(w http.ResponseWriter, r *http.Request) {
	a, err := s.db.AccountByID(r.Context(), accountID(r))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toAccountResp(a))
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentAuthKey string    `json:"current_auth_key"`
		KDF            vault.KDF `json:"kdf"`
		AuthKey        string    `json:"auth_key"`
		WrappedKey     string    `json:"wrapped_key"`
	}
	if !decode(w, r, &req) {
		return
	}
	a, err := s.db.AccountByID(r.Context(), accountID(r))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !s.checkAuthKey(a, true, req.CurrentAuthKey) {
		writeErr(w, http.StatusForbidden, "current master password is wrong")
		return
	}
	authKey, ok := decodeKey(req.AuthKey)
	if req.KDF.Validate() != nil || !ok || !validWrapped(req.WrappedKey) {
		writeErr(w, http.StatusBadRequest, "kdf, auth_key or wrapped_key is malformed")
		return
	}
	if err := s.db.ChangePassword(r.Context(), a.ID, req.KDF, authKey, req.WrappedKey, token(r)); err != nil {
		s.internal(w, r, err)
		return
	}
	a, _ = s.db.AccountByID(r.Context(), a.ID)
	writeJSON(w, http.StatusOK, toAccountResp(a))
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AuthKey string `json:"auth_key"`
	}
	if !decode(w, r, &req) {
		return
	}
	a, err := s.db.AccountByID(r.Context(), accountID(r))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if !s.checkAuthKey(a, true, req.AuthKey) {
		writeErr(w, http.StatusForbidden, "master password is wrong")
		return
	}
	if err := s.db.DeleteAccount(r.Context(), a.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	s.log.Info("account deleted", "username", a.Username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sessions(w http.ResponseWriter, r *http.Request) {
	list, err := s.db.Sessions(r.Context(), accountID(r), token(r))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": list})
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request) {
	err := s.db.DeleteSessionByID(r.Context(), accountID(r), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "no such session")
		return
	} else if err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) sync(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	items, rev, err := s.db.Changes(r.Context(), accountID(r), max(since, 0))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if items == nil {
		items = []store.Item{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev, "items": items})
}

func (s *Server) writeItems(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Writes []store.Write `json:"writes"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.Writes) == 0 || len(req.Writes) > maxBatch {
		writeErr(w, http.StatusBadRequest, "send 1 to 2000 writes")
		return
	}
	seen := map[string]bool{}
	for i, wr := range req.Writes {
		id, err := uuid.Parse(wr.ID)
		switch {
		case err != nil:
			writeErr(w, http.StatusBadRequest, "item ids must be UUIDs")
			return
		case seen[id.String()]:
			writeErr(w, http.StatusBadRequest, "an item appears twice in one batch")
			return
		case !wr.Delete && (wr.Data == "" || len(wr.Data) > maxItemBytes):
			writeErr(w, http.StatusBadRequest, "item data must be 1 byte to 256 KiB")
			return
		case wr.Delete && wr.Data != "":
			writeErr(w, http.StatusBadRequest, "a delete carries no data")
			return
		}
		seen[id.String()] = true
		req.Writes[i].ID = id.String()
		if _, err := base64.StdEncoding.DecodeString(wr.Data); err != nil {
			writeErr(w, http.StatusBadRequest, "item data must be base64")
			return
		}
	}
	rev, err := s.db.Apply(r.Context(), accountID(r), req.Writes)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revision": rev})
}
