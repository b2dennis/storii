package quick

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/b2dennis/storii/internal/client"
	"github.com/b2dennis/storii/internal/vault"
)

func testVault() *client.Vault {
	return &client.Vault{Items: map[string]vault.Item{
		"c-gh":   {Kind: vault.KindContext, Name: "GitHub", ContextType: vault.ContextWebsite, URLs: []string{"https://github.com"}},
		"c-bank": {Kind: vault.KindContext, Name: "Sparkasse", ContextType: vault.ContextWebsite, URLs: []string{"https://banking.sparkasse.de"}},
		"s-gh": {Kind: vault.KindSecret, Name: "GitHub", Type: vault.TypePassword, Contexts: []string{"c-gh"},
			Fields: map[string]string{"username": "dennis", "password": "pw1"}},
		"s-a2fa": {Kind: vault.KindSecret, Name: "GitHub", Type: vault.TypeTOTP, Contexts: []string{"c-gh"},
			Fields: map[string]string{"secret": "JBSWY3DPEHPK3PXP", "account": "dennis@example.com"}},
		"s-ghtoken": {Kind: vault.KindSecret, Name: "Deploy token", Type: vault.TypeAPIKey, Contexts: []string{"c-gh"},
			Fields: map[string]string{"key": "ghp_x"}},
		"s-bank": {Kind: vault.KindSecret, Name: "Online banking", Type: vault.TypePassword, Contexts: []string{"c-bank"},
			Fields: map[string]string{"username": "12345", "password": "pw2"}},
		"s-wifi": {Kind: vault.KindSecret, Name: "Home wifi", Type: vault.TypeNote, Notes: "hunter2"},
	}}
}

func ids(rs []Result) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return out
}

func TestSearch(t *testing.T) {
	v := testVault()
	cases := []struct {
		q      string
		recent []string
		want   []string
	}{
		{"", nil, []string{"s-ghtoken", "s-gh", "s-a2fa", "s-wifi", "s-bank"}},
		{"", []string{"s-bank"}, []string{"s-bank", "s-ghtoken", "s-gh", "s-a2fa", "s-wifi"}},
		{"git", nil, []string{"s-gh", "s-a2fa", "s-ghtoken"}}, // name prefix beats a context match
		{"sparkasse", nil, []string{"s-bank"}},                // context name
		{"banking.spark", nil, []string{"s-bank"}},            // context URL
		{"wifi", nil, []string{"s-wifi"}},                     // word prefix in the name
		{"git 2fa", nil, []string{"s-a2fa"}},                  // every word must match; type label
		{"token", nil, []string{"s-ghtoken"}},
		{"12345", nil, []string{"s-bank"}}, // username
		{"nothing", nil, nil},
	}
	for _, c := range cases {
		got := ids(Search(v, c.q, c.recent))
		if len(got) != len(c.want) {
			t.Errorf("%q: got %v, want %v", c.q, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%q: got %v, want %v", c.q, got, c.want)
				break
			}
		}
	}
	r := Search(v, "online", nil)[0]
	if r.Subtitle != "12345 · Sparkasse" || r.URL != "https://banking.sparkasse.de" || r.Has2FA {
		t.Errorf("row: %+v", r)
	}
	if gh := Search(v, "github", nil)[0]; gh.ID != "s-gh" || !gh.Has2FA {
		t.Errorf("github row: %+v", gh)
	}
}

func TestRelated2FA(t *testing.T) {
	v := testVault()
	if got := Related2FA(v, "s-gh"); got != "s-a2fa" {
		t.Errorf("got %q", got)
	}
	if got := Related2FA(v, "s-bank"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestTOTPStatus(t *testing.T) {
	it := testVault().Items["s-a2fa"]
	code, left := TOTPStatus(it, time.Unix(59, 0))
	if len(code) != 7 || code[3] != ' ' || left != 1 {
		t.Errorf("%q %d", code, left)
	}
}

func TestRecent(t *testing.T) {
	l := Recent(Recent(Recent(nil, "a"), "b"), "a")
	if len(l) != 2 || l[0] != "a" || l[1] != "b" {
		t.Errorf("%v", l)
	}
}

func TestParseHotkey(t *testing.T) {
	h, err := ParseHotkey("Ctrl+Shift+Space")
	if err != nil || !h.Ctrl || !h.Shift || h.Alt || h.Key != "SPACE" {
		t.Errorf("%+v %v", h, err)
	}
	if h, err := ParseHotkey("win+alt+f12"); err != nil || !h.Win || !h.Alt || h.Key != "F12" {
		t.Errorf("%+v %v", h, err)
	}
	for _, bad := range []string{"Shift+A", "Ctrl+", "Ctrl+Hyper+A", "Ctrl+F25", "Ctrl+Ä", "Ctrl+F01"} {
		if _, err := ParseHotkey(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "storii", "tray.json")
	c, err := LoadConfig(p)
	if err != nil || c != DefaultConfig() {
		t.Fatal(c, err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatal("defaults not written:", err)
	}
	os.WriteFile(p, []byte(`{"hotkey":"Alt+Space","lock_minutes":0}`), 0o600)
	if c, err := LoadConfig(p); err != nil || c.Hotkey != "Alt+Space" || c.LockMinutes != 10 || c.ClearSeconds != 30 {
		t.Error(c, err)
	}
	os.WriteFile(p, []byte(`{"hotkey":"Q"}`), 0o600)
	if c, err := LoadConfig(p); err == nil || c != DefaultConfig() {
		t.Error("bad hotkey accepted", c)
	}
}
