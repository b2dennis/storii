package importer

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// testdata/import/authy*.json is shared with the Android tests.
func TestAuthy(t *testing.T) {
	data, _ := os.ReadFile("../../testdata/import/authy.json")
	var cases struct {
		Password string `json:"password"`
		Tokens   []struct {
			Name, Issuer, Account, Secret, Context string
			Digits                                 int
			DuplicateOf                            *int `json:"duplicate_of"`
		} `json:"tokens"`
	}
	raw, _ := os.ReadFile("../../testdata/import/authy-cases.json")
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatal(err)
	}
	if Detect(data) != KindAuthy {
		t.Fatalf("detected %s", Detect(data))
	}
	if _, _, err := ParseOTP(data, ""); !errors.Is(err, ErrNeedPassword) {
		t.Errorf("without a password: %v", err)
	}
	if _, _, err := ParseOTP(data, "wrong"); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("with a wrong password: %v", err)
	}
	rows, failed, err := ParseOTP(data, cases.Password)
	if err != nil || len(failed) > 0 || len(rows) != len(cases.Tokens) {
		t.Fatalf("rows %d, failed %v, err %v", len(rows), failed, err)
	}
	for i, w := range cases.Tokens {
		r := rows[i]
		f := r.TOTP.Fields()
		if r.Name != w.Name || r.TOTP.Issuer != w.Issuer || r.TOTP.Account != w.Account || f[vault.FieldSecret] != w.Secret || r.TOTP.Digits != w.Digits {
			t.Errorf("token %d: %+v %v, want %+v", i, r, f, w)
		}
	}

	existing := map[string]vault.Item{
		"ctx-gh": {Kind: vault.KindContext, Name: "github.com", ContextType: vault.ContextWebsite, URLs: []string{"https://github.com"}},
	}
	n := 0
	plan := BuildOTP(existing, rows, func() string { n++; return fmt.Sprintf("new-%d", n) }, time.Now())
	for i, w := range cases.Tokens {
		l := plan.Lines[i]
		if w.DuplicateOf != nil {
			if l.Action != Skip || l.ID != plan.Lines[*w.DuplicateOf].ID {
				t.Errorf("token %d: %+v, want a skip as the duplicate of %d", i, l, *w.DuplicateOf)
			}
			continue
		}
		it := plan.Writes[l.ID]
		if l.Action != Add || it.Type != vault.TypeTOTP || it.Validate() != nil {
			t.Errorf("token %d: %+v %+v", i, l, it)
		}
		if want := w.Context; (want == "" && len(it.Contexts) != 0) || (want != "" && (len(it.Contexts) != 1 || it.Contexts[0] != want)) {
			t.Errorf("token %d: contexts %v, want %q", i, it.Contexts, want)
		}
	}
	// Importing again adds nothing.
	for id, it := range plan.Writes {
		existing[id] = it
	}
	if again := BuildOTP(existing, rows, func() string { return "x" }, time.Now()); again.Count(Add) != 0 {
		t.Errorf("second import: %+v", again.Lines)
	}
}

func TestOTPAuthList(t *testing.T) {
	data := []byte("otpauth://totp/GitHub:dennis?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\n" +
		"  otpauth://totp/Example?secret=GEZDGNBVGY3TQOJQ&digits=8  \nnot a uri\notpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1\n")
	if Detect(data) != KindOTP {
		t.Fatalf("detected %s", Detect(data))
	}
	rows, failed, err := ParseOTP(data, "")
	if err != nil || len(rows) != 2 || len(failed) != 1 || rows[0].Name != "GitHub" || rows[0].TOTP.Account != "dennis" || rows[1].TOTP.Digits != 8 {
		t.Errorf("rows %+v, failed %v, err %v", rows, failed, err)
	}
	if Detect([]byte("name,url,username,password,note\n")) != KindLogins {
		t.Error("a login CSV wasn't detected as one")
	}
}
