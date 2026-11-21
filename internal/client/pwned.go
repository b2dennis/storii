package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// PwnedURL is where Pwned asks; tests point it elsewhere.
var PwnedURL = vault.PwnedRangeURL

// Pwned asks Have I Been Pwned how often a password appears in known breaches. Only the first 5 hex digits of its
// SHA-1 are sent, with padding so the answer's size reveals nothing.
func Pwned(ctx context.Context, pw string) (int, error) {
	prefix, suffix := vault.PwnedHash(pw)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, PwnedURL+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "storii")
	res, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("breach check: %s", res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return 0, err
	}
	return vault.PwnedCount(string(b), suffix), nil
}
