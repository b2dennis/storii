// Package client talks to a storii v2 server and keeps an encrypted local copy of the vault.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// API is a thin wrapper around the HTTP endpoints.
type API struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// APIError is a non-2xx answer.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return fmt.Sprintf("server: %s (%d)", e.Message, e.Status) }

func IsUnauthorized(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.Status == http.StatusUnauthorized
}

func NewAPI(baseURL, token string) *API {
	return &API{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

func (a *API) call(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if a.Token != "" {
		req.Header.Set("Authorization", "Bearer "+a.Token)
	}
	res, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(raw, &e) != nil || e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
			if e.Error == "" {
				e.Error = res.Status
			}
		}
		return &APIError{res.StatusCode, e.Error}
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

type Account struct {
	Username   string    `json:"username"`
	KDF        vault.KDF `json:"kdf"`
	WrappedKey string    `json:"wrapped_key"`
	Revision   int64     `json:"revision"`
	CreatedAt  time.Time `json:"created_at"`
}

type SessionResp struct {
	Token   string  `json:"token"`
	Account Account `json:"account"`
}

// RemoteItem is an item as the server stores it.
type RemoteItem struct {
	ID       string `json:"id"`
	Data     string `json:"data,omitempty"`
	Deleted  bool   `json:"deleted,omitempty"`
	Revision int64  `json:"revision"`
}

type Write struct {
	ID     string `json:"id"`
	Data   string `json:"data,omitempty"`
	Delete bool   `json:"delete,omitempty"`
}

func (a *API) Ping(ctx context.Context) error {
	var r struct {
		API string `json:"api"`
	}
	if err := a.call(ctx, http.MethodGet, "/api/v2/ping", nil, &r); err != nil {
		return err
	}
	if r.API != "v2" {
		return errors.New("that is not a storii v2 server")
	}
	return nil
}

func (a *API) Prelogin(ctx context.Context, username string) (vault.KDF, error) {
	var r struct {
		KDF vault.KDF `json:"kdf"`
	}
	err := a.call(ctx, http.MethodPost, "/api/v2/prelogin", map[string]string{"username": username}, &r)
	return r.KDF, err
}

func (a *API) Register(ctx context.Context, username string, kdf vault.KDF, authKey, wrappedKey, device string) (SessionResp, error) {
	var r SessionResp
	err := a.call(ctx, http.MethodPost, "/api/v2/register", map[string]any{"username": username, "kdf": kdf,
		"auth_key": authKey, "wrapped_key": wrappedKey, "device_name": device}, &r)
	return r, err
}

func (a *API) Login(ctx context.Context, username, authKey, device string) (SessionResp, error) {
	var r SessionResp
	err := a.call(ctx, http.MethodPost, "/api/v2/login", map[string]string{"username": username,
		"auth_key": authKey, "device_name": device}, &r)
	return r, err
}

func (a *API) Logout(ctx context.Context) error {
	return a.call(ctx, http.MethodPost, "/api/v2/logout", nil, nil)
}

func (a *API) Account(ctx context.Context) (Account, error) {
	var r Account
	err := a.call(ctx, http.MethodGet, "/api/v2/account", nil, &r)
	return r, err
}

func (a *API) ChangePassword(ctx context.Context, currentAuthKey string, kdf vault.KDF, authKey, wrappedKey string) (Account, error) {
	var r Account
	err := a.call(ctx, http.MethodPut, "/api/v2/account/password", map[string]any{"current_auth_key": currentAuthKey,
		"kdf": kdf, "auth_key": authKey, "wrapped_key": wrappedKey}, &r)
	return r, err
}

func (a *API) DeleteAccount(ctx context.Context, authKey string) error {
	return a.call(ctx, http.MethodDelete, "/api/v2/account", map[string]string{"auth_key": authKey}, nil)
}

func (a *API) Sync(ctx context.Context, since int64) (int64, []RemoteItem, error) {
	var r struct {
		Revision int64        `json:"revision"`
		Items    []RemoteItem `json:"items"`
	}
	err := a.call(ctx, http.MethodGet, "/api/v2/sync?since="+strconv.FormatInt(since, 10), nil, &r)
	return r.Revision, r.Items, err
}

func (a *API) Write(ctx context.Context, writes []Write) (int64, error) {
	var r struct {
		Revision int64 `json:"revision"`
	}
	err := a.call(ctx, http.MethodPost, "/api/v2/items", map[string]any{"writes": writes}, &r)
	return r.Revision, err
}

// Get calls any GET endpoint.
func (a *API) Get(ctx context.Context, path string, out any) error {
	return a.call(ctx, http.MethodGet, path, nil, out)
}
