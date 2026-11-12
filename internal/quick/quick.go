// Package quick is the platform-independent part of the desktop quick-search apps: ranking secrets for a query,
// what each one copies, and the tray settings. The windowing lives in cmd/storii-tray.
package quick

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/vault"
)

// Result is one row in the search list.
type Result struct {
	ID       string
	Name     string
	Type     string
	Subtitle string // the username, account or key id, and the contexts
	URL      string // the first website the secret belongs to, for "open"
	Has2FA   bool   // a 2FA secret shares a context with this one (Related2FA)
	score    int
}

// Search returns the secrets matching every word of the query, best first. With an empty query it lists recently
// used secrets first, then everything by name.
func Search(v *client.Vault, query string, recent []string) []Result {
	words := strings.Fields(strings.ToLower(query))
	ctxs := v.List(vault.KindContext)
	byID := map[string]client.Entry{}
	for _, c := range ctxs {
		byID[c.ID] = c
	}
	var out []Result
	for _, e := range v.List(vault.KindSecret) {
		var names, hay []string
		url := ""
		for _, id := range e.Contexts {
			c, ok := byID[id]
			if !ok {
				continue
			}
			names = append(names, c.Name)
			hay = append(hay, strings.ToLower(c.Name))
			for _, u := range c.URLs {
				hay = append(hay, strings.ToLower(u))
				if url == "" && c.ContextType == vault.ContextWebsite {
					url = u
				}
			}
			for _, p := range c.AndroidPackages {
				hay = append(hay, strings.ToLower(p))
			}
		}
		user := Username(e.Item)
		hay = append(hay, strings.ToLower(user), TypeLabel(e.Type), strings.ToLower(e.Field(vault.FieldIssuer)))
		score, ok := match(strings.ToLower(e.Name), hay, words)
		if !ok {
			continue
		}
		if i := slices.Index(recent, e.ID); i >= 0 {
			score += 50 - min(i, 40) // recent use breaks ties and lifts weak matches a little
		}
		sub := user
		if len(names) > 0 {
			sub = strings.Join(slices.DeleteFunc([]string{user, strings.Join(names, ", ")}, func(s string) bool { return s == "" }), " · ")
		}
		out = append(out, Result{ID: e.ID, Name: e.Name, Type: e.Type, Subtitle: sub, URL: url,
			Has2FA: e.Type != vault.TypeTOTP && e.Type != vault.TypeCard && Related2FA(v, e.ID) != "", score: score})
	}
	slices.SortStableFunc(out, func(a, b Result) int {
		return cmp.Or(cmp.Compare(b.score, a.score), cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)),
			cmp.Compare(typeRank(a.Type), typeRank(b.Type)), cmp.Compare(a.ID, b.ID))
	})
	return out
}

// typeRank orders secrets of the same name: the login before its 2FA code.
func typeRank(t string) int {
	switch t {
	case vault.TypePassword:
		return 0
	case vault.TypeAPIKey:
		return 1
	case vault.TypeTOTP:
		return 2
	}
	return 3
}

// match scores how well the words match a name and other searchable text. Every word must match somewhere.
func match(name string, hay []string, words []string) (int, bool) {
	total := 0
	for _, w := range words {
		best := 0
		switch {
		case name == w:
			best = 100
		case strings.HasPrefix(name, w):
			best = 60
		case wordPrefix(name, w):
			best = 40
		case strings.Contains(name, w):
			best = 20
		}
		for _, h := range hay {
			if best >= 10 {
				break
			}
			if strings.Contains(h, w) {
				best = 10
			}
		}
		if best == 0 {
			return 0, false
		}
		total += best
	}
	return total, true
}

// wordPrefix reports whether w starts any word of s ("hub" in "git hub", "bank" in "my-bank").
func wordPrefix(s, w string) bool {
	prevAlnum := false
	for i, r := range s {
		alnum := unicode.IsLetter(r) || unicode.IsDigit(r)
		if alnum && !prevAlnum && strings.HasPrefix(s[i:], w) {
			return true
		}
		prevAlnum = alnum
	}
	return false
}

// TypeLabel is the short name shown for a secret type.
func TypeLabel(t string) string {
	switch t {
	case vault.TypePassword:
		return "password"
	case vault.TypeTOTP:
		return "2fa"
	case vault.TypeAPIKey:
		return "api key"
	case vault.TypeNote:
		return "note"
	}
	return t
}

// Username is the identifier copied by "copy username": the login, the 2FA account or the key id.
func Username(it vault.Item) string {
	switch it.Type {
	case vault.TypePassword:
		return it.Field(vault.FieldUsername)
	case vault.TypeTOTP:
		return it.Field(vault.FieldAccount)
	case vault.TypeAPIKey:
		return it.Field(vault.FieldKeyID)
	case vault.TypePasskey:
		return it.Field("user_name")
	case vault.TypeCard:
		// Lists show the card's last digits where other secrets show a username.
		if n := it.Field(vault.FieldNumber); n != "" {
			return vault.CardMasked(n)
		}
	}
	return ""
}

// What names what a copy of a secret's main value puts on the clipboard.
func What(t string) string {
	switch t {
	case vault.TypePassword:
		return "password"
	case vault.TypeTOTP:
		return "2FA code"
	case vault.TypeAPIKey:
		return "API key"
	case vault.TypeCard:
		return "card number"
	case vault.TypePasskey:
		return "passkey"
	}
	return "note"
}

// Related2FA returns the id of a 2FA secret that shares a context with the given secret, so "copy 2FA code" works
// from a login's row. It prefers one with the same name.
func Related2FA(v *client.Vault, id string) string {
	it, ok := v.Items[id]
	if !ok || len(it.Contexts) == 0 {
		return ""
	}
	best := ""
	for _, e := range v.List(vault.KindSecret) {
		if e.Type != vault.TypeTOTP || e.ID == id {
			continue
		}
		if slices.ContainsFunc(e.Contexts, func(c string) bool { return slices.Contains(it.Contexts, c) }) {
			if strings.EqualFold(e.Name, it.Name) {
				return e.ID
			}
			if best == "" {
				best = e.ID
			}
		}
	}
	return best
}

// TOTPStatus is the current code, grouped for reading, and the seconds it stays valid, for a 2FA row.
func TOTPStatus(it vault.Item, now time.Time) (string, int) {
	t, err := vault.TOTPFromFields(it.Fields)
	if err != nil {
		return "", 0
	}
	c := t.Code(now)
	if len(c) == 6 || len(c) == 8 {
		c = c[:len(c)/2] + " " + c[len(c)/2:]
	}
	return c, int(t.Remaining(now).Round(time.Second) / time.Second)
}

// Recent keeps the most recently used ids first.
func Recent(list []string, id string) []string {
	list = slices.DeleteFunc(slices.Clone(list), func(s string) bool { return s == id })
	return slices.Insert(list, 0, id)[:min(len(list)+1, 20)]
}

// Config is the tray app's settings file.
type Config struct {
	Hotkey       string `json:"hotkey"`        // e.g. "Ctrl+Shift+Space"
	LockMinutes  int    `json:"lock_minutes"`  // lock after this long without using the search
	ClearSeconds int    `json:"clear_seconds"` // empty the clipboard this long after a copy
}

func DefaultConfig() Config {
	return Config{Hotkey: "Ctrl+Shift+Space", LockMinutes: 10, ClearSeconds: 30}
}

// LoadConfig reads the settings, writing the defaults when there is no file yet so there is one to edit.
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_ = os.MkdirAll(filepath.Dir(path), 0o700)
		b, _ := json.MarshalIndent(c, "", "  ")
		_ = os.WriteFile(path, append(b, '\n'), 0o600)
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return DefaultConfig(), fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if _, err := ParseHotkey(c.Hotkey); err != nil {
		return DefaultConfig(), err
	}
	if c.LockMinutes <= 0 {
		c.LockMinutes = DefaultConfig().LockMinutes
	}
	if c.ClearSeconds <= 0 {
		c.ClearSeconds = DefaultConfig().ClearSeconds
	}
	return c, nil
}

// Hotkey is a parsed shortcut. Key is upper case: a letter, a digit, F1-F24 or a named key.
type Hotkey struct {
	Ctrl, Alt, Shift, Win bool
	Key                   string
}

var namedKeys = []string{"SPACE", "ENTER", "TAB", "INSERT", "HOME", "END", "PAGEUP", "PAGEDOWN"}

func ParseHotkey(s string) (Hotkey, error) {
	var h Hotkey
	parts := strings.Split(strings.ReplaceAll(s, " ", ""), "+")
	for i, p := range parts {
		u := strings.ToUpper(p)
		if i < len(parts)-1 {
			switch u {
			case "CTRL", "CONTROL":
				h.Ctrl = true
			case "ALT":
				h.Alt = true
			case "SHIFT":
				h.Shift = true
			case "WIN", "SUPER", "CMD":
				h.Win = true
			default:
				return h, fmt.Errorf("hotkey %q: unknown modifier %q", s, p)
			}
			continue
		}
		switch {
		case len(u) == 1 && (u[0] >= 'A' && u[0] <= 'Z' || u[0] >= '0' && u[0] <= '9'):
		case len(u) >= 2 && u[0] == 'F' && isFKey(u[1:]):
		case slices.Contains(namedKeys, u):
		default:
			return h, fmt.Errorf("hotkey %q: unknown key %q", s, p)
		}
		h.Key = u
	}
	if !h.Ctrl && !h.Alt && !h.Win {
		return h, fmt.Errorf("hotkey %q needs Ctrl, Alt or Win", s)
	}
	return h, nil
}

func isFKey(n string) bool {
	var i int
	_, err := fmt.Sscanf(n, "%d", &i)
	return err == nil && i >= 1 && i <= 24 && fmt.Sprint(i) == n
}
