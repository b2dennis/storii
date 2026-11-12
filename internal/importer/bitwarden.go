package importer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// KindBitwarden is Bitwarden's JSON export (not the encrypted one): logins with their 2FA codes and passkeys, and
// cards. Shared cases in testdata/import/bitwarden*.json.
const KindBitwarden = "bitwarden"

// ErrEncryptedBitwarden is an export made with "File format: .json (Encrypted)".
var ErrEncryptedBitwarden = errors.New(`this Bitwarden export is encrypted: export again with the file format ".json", not ".json (Encrypted)"`)

// Passkey fields, as the storii clients write them.
const (
	FieldCredentialID    = "credential_id"
	FieldRPID            = "rp_id"
	FieldUserHandle      = "user_handle"
	FieldUserName        = "user_name"
	FieldUserDisplayName = "user_display_name"
	FieldPrivateKey      = "private_key"
)

// CardRow is one card from an export. Expiry is MM/YY.
type CardRow struct{ Name, Cardholder, Number, Expiry, CVC, Note string }

// PasskeyRow is one passkey from an export, with the passkey fields above.
type PasskeyRow struct {
	Name   string
	Fields map[string]string
}

// Bitwarden is what a Bitwarden JSON export holds that storii can use.
type Bitwarden struct {
	Logins   []Row
	Codes    []OTPRow
	Cards    []CardRow
	Passkeys []PasskeyRow
	Failed   []string // entries storii couldn't read (a 2FA code or passkey it doesn't support)
}

// Count is the number of entries found.
func (b Bitwarden) Count() int { return len(b.Logins) + len(b.Codes) + len(b.Cards) + len(b.Passkeys) }

type bwExport struct {
	Encrypted *bool `json:"encrypted"`
	Items     []struct {
		Type  int    `json:"type"` // 1 login, 2 note, 3 card, 4 identity, 5 SSH key
		Name  string `json:"name"`
		Notes string `json:"notes"`
		Login *struct {
			URIs []struct {
				URI string `json:"uri"`
			} `json:"uris"`
			Username string `json:"username"`
			Password string `json:"password"`
			TOTP     string `json:"totp"`
			Fido2    []struct {
				CredentialID    string `json:"credentialId"`
				KeyAlgorithm    string `json:"keyAlgorithm"`
				KeyCurve        string `json:"keyCurve"`
				KeyValue        string `json:"keyValue"`
				RPID            string `json:"rpId"`
				RPName          string `json:"rpName"`
				UserHandle      string `json:"userHandle"`
				UserName        string `json:"userName"`
				UserDisplayName string `json:"userDisplayName"`
			} `json:"fido2Credentials"`
		} `json:"login"`
		Card *struct {
			CardholderName string `json:"cardholderName"`
			Number         string `json:"number"`
			ExpMonth       string `json:"expMonth"`
			ExpYear        string `json:"expYear"`
			Code           string `json:"code"`
		} `json:"card"`
	} `json:"items"`
}

// isBitwarden reports whether data is a Bitwarden JSON export, encrypted or not.
func isBitwarden(data []byte) bool {
	var probe struct {
		Encrypted *bool            `json:"encrypted"`
		Items     *json.RawMessage `json:"items"`
	}
	return json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &probe) == nil && probe.Encrypted != nil
}

var guid = regexp.MustCompile(`^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$`)

// ParseBitwarden reads an unencrypted Bitwarden JSON export.
func ParseBitwarden(data []byte) (Bitwarden, error) {
	var ex bwExport
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &ex); err != nil || ex.Encrypted == nil {
		return Bitwarden{}, errors.New("this isn't a Bitwarden JSON export")
	}
	if *ex.Encrypted {
		return Bitwarden{}, ErrEncryptedBitwarden
	}
	var b Bitwarden
	for _, it := range ex.Items {
		switch {
		case it.Type == 1 && it.Login != nil:
			l := it.Login
			url := ""
			if len(l.URIs) > 0 {
				url = strings.TrimSpace(l.URIs[0].URI)
			}
			if l.Password != "" {
				b.Logins = append(b.Logins, Row{Name: strings.TrimSpace(it.Name), URL: url,
					Username: strings.TrimSpace(l.Username), Password: l.Password, Note: strings.TrimSpace(it.Notes)})
			}
			if code := strings.TrimSpace(l.TOTP); code != "" {
				if t, err := bwTOTP(code, it.Name, l.Username); err == nil {
					b.Codes = append(b.Codes, OTPRow{Name: otpName(t, it.Name), TOTP: t})
				} else {
					b.Failed = append(b.Failed, it.Name+" (2FA code: "+err.Error()+")")
				}
			}
			for _, f := range l.Fido2 {
				fields, err := bwPasskey(f.CredentialID, f.KeyAlgorithm, f.KeyCurve, f.KeyValue, f.UserHandle)
				if err != nil || f.RPID == "" {
					if err == nil {
						err = errors.New("no website")
					}
					b.Failed = append(b.Failed, it.Name+" (passkey: "+err.Error()+")")
					continue
				}
				fields[FieldRPID] = strings.ToLower(f.RPID)
				fields[FieldUserName] = f.UserName
				fields[FieldUserDisplayName] = f.UserDisplayName
				name := f.RPName
				if name == "" {
					name = f.RPID
				}
				b.Passkeys = append(b.Passkeys, PasskeyRow{Name: name, Fields: fields})
			}
		case it.Type == 3 && it.Card != nil:
			c := it.Card
			exp := ""
			if c.ExpMonth != "" && c.ExpYear != "" {
				exp = vault.NormalizeExpiry(c.ExpMonth + "/" + c.ExpYear)
			}
			b.Cards = append(b.Cards, CardRow{Name: strings.TrimSpace(it.Name), Cardholder: strings.TrimSpace(c.CardholderName),
				Number: vault.CardDigits(c.Number), Expiry: exp, CVC: strings.TrimSpace(c.Code), Note: strings.TrimSpace(it.Notes)})
		}
	}
	return b, nil
}

// bwTOTP reads a login's 2FA field: an otpauth:// URI or a bare base32 secret (Steam codes aren't supported).
func bwTOTP(code, name, user string) (vault.TOTP, error) {
	if strings.HasPrefix(strings.ToLower(code), "otpauth://") {
		return vault.ParseOTPAuth(code)
	}
	if strings.Contains(code, "://") {
		return vault.TOTP{}, errors.New("unsupported kind")
	}
	return vault.TOTPFromFields(map[string]string{vault.FieldSecret: code, vault.FieldIssuer: name, vault.FieldAccount: user})
}

// bwPasskey converts Bitwarden's passkey encoding: credential ids are GUIDs (16 bytes) or "b64."-prefixed
// base64url, the key is PKCS#8 in base64url. Only ES256 (P-256) keys exist in practice.
func bwPasskey(credID, alg, curve, key, userHandle string) (map[string]string, error) {
	if !strings.EqualFold(alg, "ECDSA") || !strings.EqualFold(curve, "P-256") {
		return nil, errors.New("unsupported key type " + alg + " " + curve)
	}
	var id []byte
	var err error
	switch {
	case strings.HasPrefix(credID, "b64."):
		id, err = unb64(credID[4:])
	case guid.MatchString(credID):
		id, err = hex.DecodeString(strings.ReplaceAll(credID, "-", ""))
	default:
		id, err = unb64(credID)
	}
	if err != nil || len(id) == 0 {
		return nil, errors.New("unreadable credential id")
	}
	der, err := unb64(key)
	if err != nil {
		return nil, errors.New("unreadable key")
	}
	pk, err := x509.ParsePKCS8PrivateKey(der)
	if ec, ok := pk.(*ecdsa.PrivateKey); err != nil || !ok || ec.Curve != elliptic.P256() {
		return nil, errors.New("unreadable key")
	}
	fields := map[string]string{FieldCredentialID: b64(id), FieldPrivateKey: b64(der)}
	if userHandle != "" {
		h, err := unb64(userHandle)
		if err != nil {
			return nil, errors.New("unreadable user handle")
		}
		fields[FieldUserHandle] = b64(h)
	}
	return fields, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// unb64 accepts base64url or standard base64, padded or not.
func unb64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimSpace(s)), "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// Build matches everything in the export against the vault: logins (as Build does), 2FA codes (as BuildOTP),
// then cards (skipped when a card with the same number exists) and passkeys (skipped when the credential id exists).
func (b Bitwarden) Build(existing map[string]vault.Item, newID func() string, now time.Time) Plan {
	now = now.UTC().Truncate(time.Second)
	items := make(map[string]vault.Item, len(existing))
	for id, it := range existing {
		items[id] = it
	}
	plan := Plan{Writes: map[string]vault.Item{}}
	merge := func(p Plan) {
		for id, it := range p.Writes {
			items[id] = it
			plan.Writes[id] = it
		}
		plan.Lines = append(plan.Lines, p.Lines...)
	}
	merge(Build(items, b.Logins, newID, now))
	merge(BuildOTP(items, b.Codes, newID, now))
	put := func(id string, it vault.Item) {
		items[id] = it
		plan.Writes[id] = it
	}

	for _, c := range b.Cards {
		name := c.Name
		if name == "" {
			name = strings.TrimSpace(cardBrandName(c.Number) + " " + last4(c.Number))
		}
		line := Line{Name: name, Site: vault.CardMasked(c.Number)}
		if c.Number == "" {
			line.Action = Invalid
			plan.Lines = append(plan.Lines, line)
			continue
		}
		dup := ""
		for _, id := range sortedIDs(items) {
			it := items[id]
			if it.Kind == vault.KindSecret && it.Type == vault.TypeCard && vault.CardDigits(it.Fields[vault.FieldNumber]) == c.Number {
				dup = id
				break
			}
		}
		if dup != "" {
			line.Action, line.ID = Skip, dup
		} else {
			fields := map[string]string{vault.FieldNumber: c.Number}
			for k, v := range map[string]string{vault.FieldCardholder: c.Cardholder, vault.FieldExpiry: c.Expiry, vault.FieldCVC: c.CVC} {
				if v != "" {
					fields[k] = v
				}
			}
			id := newID()
			put(id, vault.Item{Kind: vault.KindSecret, Type: vault.TypeCard, Name: name, Fields: fields, Notes: c.Note,
				CreatedAt: now, UpdatedAt: now})
			line.Action, line.ID = Add, id
		}
		plan.Lines = append(plan.Lines, line)
	}

	for _, p := range b.Passkeys {
		rp := p.Fields[FieldRPID]
		line := Line{Name: p.Name, Site: rp}
		dup := ""
		for _, id := range sortedIDs(items) {
			it := items[id]
			if it.Kind == vault.KindSecret && it.Type == vault.TypePasskey && it.Fields[FieldCredentialID] == p.Fields[FieldCredentialID] {
				dup = id
				break
			}
		}
		if dup != "" {
			line.Action, line.ID = Skip, dup
			plan.Lines = append(plan.Lines, line)
			continue
		}
		s := site{host: rp}
		ctxID := findContext(items, s)
		if ctxID == "" {
			ctxID = newID()
			put(ctxID, vault.Item{Kind: vault.KindContext, Name: rp, ContextType: vault.ContextWebsite,
				URLs: []string{"https://" + rp}, CreatedAt: now, UpdatedAt: now})
		}
		id := newID()
		put(id, vault.Item{Kind: vault.KindSecret, Type: vault.TypePasskey, Name: p.Name, Contexts: []string{ctxID},
			Fields: p.Fields, CreatedAt: now, UpdatedAt: now})
		line.Action, line.ID = Add, id
		plan.Lines = append(plan.Lines, line)
	}
	return plan
}

func last4(number string) string {
	if len(number) > 4 {
		return number[len(number)-4:]
	}
	return number
}

// cardBrandName is how a brand is written in a name ("Visa", "American Express").
func cardBrandName(number string) string {
	switch b := vault.CardBrand(number); b {
	case "":
		return "Card"
	case "amex":
		return "American Express"
	case "jcb":
		return "JCB"
	case "unionpay":
		return "UnionPay"
	default:
		return strings.ToUpper(b[:1]) + b[1:]
	}
}
