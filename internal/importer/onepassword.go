package importer

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/b2dennis/storii/internal/vault"
)

// KindOnePassword is 1Password's .1pux export (a zip holding export.data), or that export.data on its own: logins
// with their 2FA codes, passwords, and cards. 1Password leaves passkeys out of its exports, and archived items are
// skipped. Shared cases in testdata/import/1password*.json.
const KindOnePassword = "1password"

// onePUX is export.data: accounts › vaults › items.
type onePUX struct {
	Accounts []struct {
		Vaults []struct {
			Items []onePUXItem `json:"items"`
		} `json:"vaults"`
	} `json:"accounts"`
}

type onePUXItem struct {
	State        string `json:"state"`        // "active" or "archived"
	CategoryUUID string `json:"categoryUuid"` // 001 login, 002 credit card, 005 password
	Overview     struct {
		Title string `json:"title"`
		URL   string `json:"url"`
		URLs  []struct {
			URL string `json:"url"`
		} `json:"urls"`
	} `json:"overview"`
	Details struct {
		LoginFields []struct {
			Value       string `json:"value"`
			Designation string `json:"designation"` // "username" or "password"
		} `json:"loginFields"`
		NotesPlain string `json:"notesPlain"`
		Password   string `json:"password"`
		Sections   []struct {
			Fields []struct {
				Title string                     `json:"title"`
				ID    string                     `json:"id"`
				Value map[string]json.RawMessage `json:"value"` // one key: string, concealed, totp, creditCardNumber, monthYear, ...
			} `json:"fields"`
		} `json:"sections"`
	} `json:"details"`
}

// onePUXData returns export.data from a .1pux zip, or the data itself when it already is export.data.
func onePUXData(data []byte) ([]byte, bool) {
	if bytes.HasPrefix(data, []byte("PK\x03\x04")) {
		z, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, false
		}
		for _, f := range z.File {
			if f.Name != "export.data" {
				continue
			}
			r, err := f.Open()
			if err != nil {
				return nil, false
			}
			defer r.Close()
			b, err := io.ReadAll(io.LimitReader(r, 256<<20))
			return b, err == nil
		}
		return nil, false
	}
	var probe struct {
		Accounts []struct {
			Vaults *json.RawMessage `json:"vaults"`
		} `json:"accounts"`
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if json.Unmarshal(data, &probe) != nil || len(probe.Accounts) == 0 || probe.Accounts[0].Vaults == nil {
		return nil, false
	}
	return data, true
}

func isOnePassword(data []byte) bool {
	_, ok := onePUXData(data)
	return ok
}

// ParseOnePassword reads a .1pux export (or its export.data). The result has the same shape as a Bitwarden export.
func ParseOnePassword(data []byte) (Bitwarden, error) {
	raw, ok := onePUXData(data)
	var ex onePUX
	if !ok || json.Unmarshal(raw, &ex) != nil {
		return Bitwarden{}, errors.New("this isn't a 1Password export (.1pux)")
	}
	var b Bitwarden
	for _, a := range ex.Accounts {
		for _, v := range a.Vaults {
			for _, it := range v.Items {
				if it.State == "archived" {
					continue
				}
				b.addOnePassword(it)
			}
		}
	}
	return b, nil
}

// str is a field value's text: a JSON string, or a number (monthYear) as digits.
func str(v map[string]json.RawMessage, key string) string {
	raw, ok := v[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func (b *Bitwarden) addOnePassword(it onePUXItem) {
	name := strings.TrimSpace(it.Overview.Title)
	note := strings.TrimSpace(it.Details.NotesPlain)
	url := strings.TrimSpace(it.Overview.URL)
	if url == "" && len(it.Overview.URLs) > 0 {
		url = strings.TrimSpace(it.Overview.URLs[0].URL)
	}
	field := func(id string) map[string]json.RawMessage {
		for _, s := range it.Details.Sections {
			for _, f := range s.Fields {
				if f.ID == id {
					return f.Value
				}
			}
		}
		return nil
	}
	switch it.CategoryUUID {
	case "001", "005": // login, password
		user, pw := "", it.Details.Password
		for _, f := range it.Details.LoginFields {
			switch f.Designation {
			case "username":
				user = strings.TrimSpace(f.Value)
			case "password":
				pw = f.Value
			}
		}
		if pw != "" {
			b.Logins = append(b.Logins, Row{Name: name, URL: url, Username: user, Password: pw, Note: note})
		}
		for _, s := range it.Details.Sections {
			for _, f := range s.Fields {
				code := str(f.Value, "totp")
				if code == "" {
					continue
				}
				if t, err := bwTOTP(code, name, user); err == nil {
					b.Codes = append(b.Codes, OTPRow{Name: otpName(t, name), TOTP: t})
				} else {
					b.Failed = append(b.Failed, name+" (2FA code: "+err.Error()+")")
				}
			}
		}
	case "002": // credit card
		exp := ""
		// monthYear is YYYYMM, e.g. 202703.
		if my := str(field("expiry"), "monthYear"); len(my) == 6 {
			exp = vault.NormalizeExpiry(fmt.Sprintf("%s/%s", my[4:], my[2:4]))
		}
		cvc := str(field("cvv"), "concealed")
		if cvc == "" {
			cvc = str(field("cvv"), "string")
		}
		b.Cards = append(b.Cards, CardRow{Name: name, Cardholder: str(field("cardholder"), "string"),
			Number: vault.CardDigits(str(field("ccnum"), "creditCardNumber")), Expiry: exp, CVC: cvc, Note: note})
	}
}
