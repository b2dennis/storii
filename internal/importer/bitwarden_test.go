package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// testdata/import/bitwarden*.json is shared with the Android tests.
func TestBitwardenSharedCases(t *testing.T) {
	data, err := os.ReadFile("../../testdata/import/bitwarden.json")
	if err != nil {
		t.Fatal(err)
	}
	sharedCases(t, data, "bitwarden-cases.json", KindBitwarden, ParseBitwarden)
}

// sharedCases imports data (a whole-vault export) into the vault of testdata/import/<casesFile> and compares.
func sharedCases(t *testing.T, data []byte, casesFile, kind string, parse func([]byte) (Bitwarden, error)) {
	t.Helper()
	if k := Detect(data); k != kind {
		t.Fatalf("detected %s", k)
	}
	var cases struct {
		Existing map[string]vault.Item `json:"existing"`
		Failed   []string              `json:"failed"`
		Lines    []struct {
			Action   string            `json:"action"`
			ID       string            `json:"id"`
			Name     string            `json:"name"`
			Type     string            `json:"type"`
			Contexts []string          `json:"contexts"`
			Notes    string            `json:"notes"`
			Fields   map[string]string `json:"fields"`
		} `json:"lines"`
		NewContexts map[string]vault.Item `json:"new_contexts"`
	}
	raw, _ := os.ReadFile("../../testdata/import/" + casesFile)
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	var vec struct {
		Passkey map[string]string `json:"passkey"`
	}
	raw, _ = os.ReadFile("../../testdata/passkey.json")
	_ = json.Unmarshal(raw, &vec)

	b, err := parse(data)
	if err != nil {
		t.Fatal(err)
	}
	var failed []string
	for _, f := range b.Failed {
		failed = append(failed, f[:strings.Index(f, " (")])
	}
	if !slices.Equal(failed, cases.Failed) {
		t.Errorf("failed %q, want %q", b.Failed, cases.Failed)
	}
	n := 0
	plan := b.Build(cases.Existing, func() string { n++; return fmt.Sprintf("new-%d", n) }, time.Unix(1700000000, 0))
	if len(plan.Lines) != len(cases.Lines) {
		t.Fatalf("%d lines, want %d: %+v", len(plan.Lines), len(cases.Lines), plan.Lines)
	}
	for i, want := range cases.Lines {
		got := plan.Lines[i]
		if got.Action != want.Action || got.ID != want.ID || got.Name != want.Name {
			t.Errorf("line %d: %+v, want %s %s %s", i+1, got, want.Action, want.ID, want.Name)
			continue
		}
		if want.Action != Add {
			continue
		}
		it := plan.Writes[got.ID]
		fields := maps.Clone(it.Fields)
		if it.Type == vault.TypePasskey {
			if fields[FieldPrivateKey] != vec.Passkey["private_key"] {
				t.Errorf("line %d: private key %q", i+1, fields[FieldPrivateKey])
			}
			delete(fields, FieldPrivateKey)
		}
		if it.Type != want.Type || it.Name != want.Name || it.Notes != want.Notes || !slices.Equal(it.Contexts, want.Contexts) ||
			!maps.Equal(fields, want.Fields) {
			t.Errorf("line %d: wrote %+v, want %+v", i+1, it, want)
		}
	}
	for id, want := range cases.NewContexts {
		got := plan.Writes[id]
		if got.Kind != want.Kind || got.Name != want.Name || got.ContextType != want.ContextType || !slices.Equal(got.URLs, want.URLs) {
			t.Errorf("context %s: %+v, want %+v", id, got, want)
		}
	}
	adds := len(cases.NewContexts)
	for _, l := range cases.Lines {
		if l.Action == Add {
			adds++
		}
	}
	if len(plan.Writes) != adds {
		t.Errorf("%d writes, want %d", len(plan.Writes), adds)
	}

	// Importing the same file again changes nothing.
	merged := maps.Clone(cases.Existing)
	maps.Copy(merged, plan.Writes)
	again := b.Build(merged, func() string { return "x" }, time.Now())
	if len(again.Writes) != 0 {
		t.Errorf("second import writes %d items", len(again.Writes))
	}
}

func TestBitwardenEncrypted(t *testing.T) {
	data := []byte(`{"encrypted": true, "passwordProtected": true, "data": "2.abc"}`)
	if Detect(data) != KindBitwarden {
		t.Fatal("not detected")
	}
	if _, err := ParseBitwarden(data); !errors.Is(err, ErrEncryptedBitwarden) {
		t.Fatalf("err %v", err)
	}
	if Detect([]byte("name,url,username,password\n")) != KindLogins {
		t.Fatal("CSV detected as Bitwarden")
	}
}
