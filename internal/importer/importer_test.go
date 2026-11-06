package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

type expectedRow struct {
	Action     string      `json:"action"`
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Username   string      `json:"username"`
	Password   string      `json:"password"`
	Notes      string      `json:"notes"`
	Context    string      `json:"context"`
	NewContext *vault.Item `json:"new_context"`
	Differs    bool        `json:"differs"`
}

// testdata/import is shared with the Android tests.
func TestSharedCases(t *testing.T) {
	f, err := os.Open("../../testdata/import/google.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := ParseCSV(f)
	if err != nil {
		t.Fatal(err)
	}
	var cases struct {
		Existing map[string]vault.Item `json:"existing"`
		Rows     []expectedRow         `json:"rows"`
	}
	raw, _ := os.ReadFile("../../testdata/import/cases.json")
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if len(rows) != len(cases.Rows) {
		t.Fatalf("parsed %d rows, want %d", len(rows), len(cases.Rows))
	}
	n := 0
	newID := func() string { n++; return fmt.Sprintf("new-%d", n) }
	plan := Build(cases.Existing, rows, newID, time.Unix(1700000000, 0))
	for i, want := range cases.Rows {
		got := plan.Lines[i]
		if got.Action != want.Action {
			t.Errorf("row %d: action %s, want %s", i+1, got.Action, want.Action)
			continue
		}
		switch want.Action {
		case Username:
			it := plan.Writes[want.ID]
			if got.ID != want.ID || it.Fields[vault.FieldUsername] != want.Username || it.Fields[vault.FieldPassword] == "" {
				t.Errorf("row %d: updated %s to %+v", i+1, got.ID, it.Fields)
			}
		case Add:
			it := plan.Writes[got.ID]
			if it.Name != want.Name || it.Fields[vault.FieldUsername] != want.Username || it.Fields[vault.FieldPassword] != want.Password ||
				it.Notes != want.Notes || got.Differs != want.Differs {
				t.Errorf("row %d: added %+v (differs %v), want %+v", i+1, it, got.Differs, want)
			}
			switch {
			case want.Context != "":
				if len(it.Contexts) != 1 || it.Contexts[0] != want.Context {
					t.Errorf("row %d: contexts %v, want %s", i+1, it.Contexts, want.Context)
				}
			case want.NewContext != nil:
				if len(it.Contexts) != 1 || !strings.HasPrefix(it.Contexts[0], "new-") {
					t.Fatalf("row %d: contexts %v, want a new one", i+1, it.Contexts)
				}
				c, w := plan.Writes[it.Contexts[0]], *want.NewContext
				if c.Name != w.Name || c.ContextType != w.ContextType || fmt.Sprint(c.URLs) != fmt.Sprint(w.URLs) ||
					fmt.Sprint(c.AndroidPackages) != fmt.Sprint(w.AndroidPackages) {
					t.Errorf("row %d: new context %+v, want %+v", i+1, c, w)
				}
			default:
				if len(it.Contexts) != 0 {
					t.Errorf("row %d: contexts %v, want none", i+1, it.Contexts)
				}
			}
		}
	}
	for id, it := range plan.Writes {
		if err := it.Validate(); err != nil {
			t.Errorf("%s: %v", id, err)
		}
	}
	// Importing the same file again changes nothing.
	after := map[string]vault.Item{}
	for id, it := range cases.Existing {
		after[id] = it
	}
	for id, it := range plan.Writes {
		after[id] = it
	}
	again := Build(after, rows, newID, time.Now())
	if len(again.Writes) != 0 || again.Count(Add) != 0 {
		t.Errorf("second import wrote %d items: %+v", len(again.Writes), again.Lines)
	}
}

func TestOtherExports(t *testing.T) {
	for name, csv := range map[string]string{
		"firefox":   "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://github.com\",\"dennis\",\"pw\",,\"https://github.com\",\"{x}\",\"1\",\"1\",\"1\"\n",
		"bitwarden": "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n,,login,GitHub,,,0,https://github.com,dennis,pw,\n",
		"1password": "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nGitHub,https://github.com,dennis,pw,,false,false,,\n",
	} {
		rows, err := ParseCSV(strings.NewReader("\uFEFF" + csv))
		if err != nil || len(rows) != 1 || rows[0].URL != "https://github.com" || rows[0].Username != "dennis" || rows[0].Password != "pw" {
			t.Errorf("%s: %+v, %v", name, rows, err)
		}
	}
	if _, err := ParseCSV(strings.NewReader("a,b\n1,2\n")); err == nil {
		t.Error("a CSV without a password column was accepted")
	}
}
