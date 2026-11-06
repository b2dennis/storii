package importer

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha1"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/b2dennis/storii/internal/vault"
)

// Kinds of export files.
const (
	KindLogins = "logins" // a CSV of logins (Google Password Manager and others)
	KindAuthy  = "authy"  // Authy tokens, encrypted with the Authy backup password
	KindOTP    = "otp"    // 2FA secrets in the clear: otpauth:// URIs, or Authy tokens decrypted by another tool
)

// Detect tells which kind of export data is.
func Detect(data []byte) string {
	s := strings.TrimSpace(string(bytes.TrimPrefix(data, []byte("\uFEFF"))))
	switch {
	case strings.Contains(s, "encrypted_seed"):
		return KindAuthy
	case strings.Contains(s, "decrypted_seed"), strings.Contains(strings.ToLower(s), "otpauth://totp/"):
		return KindOTP
	}
	return KindLogins
}

// OTPRow is one 2FA secret from an export.
type OTPRow struct {
	Name string
	TOTP vault.TOTP
}

// ErrNeedPassword is returned for Authy exports when no backup password was given.
var ErrNeedPassword = errors.New("this Authy export is encrypted with your Authy backup password")

// ErrWrongPassword means no token could be decrypted with the password given.
var ErrWrongPassword = errors.New("none of the tokens could be decrypted: is that your Authy backup password?")

// ParseOTP reads 2FA secrets: Authy token exports (JSON, or CSV with the same columns; decrypted with the Authy
// backup password), the same tokens already decrypted ("decrypted_seed"), or text with otpauth:// URIs. Tokens that
// can't be read are listed in failed; the others are still returned.
func ParseOTP(data []byte, authyPassword string) (rows []OTPRow, failed []string, err error) {
	data = bytes.TrimPrefix(data, []byte("\uFEFF"))
	kind := Detect(data)
	if kind == KindAuthy && authyPassword == "" {
		return nil, nil, ErrNeedPassword
	}
	tokens := authyTokens(data)
	if len(tokens) == 0 {
		// otpauth:// URIs, one per line or anywhere in the text (Aegis, 2FAS and others export these).
		for _, f := range strings.FieldsFunc(string(data), func(r rune) bool { return strings.ContainsRune(" \t\r\n\",'<>[]", r) }) {
			if !strings.HasPrefix(strings.ToLower(f), "otpauth://") {
				continue
			}
			t, err := vault.ParseOTPAuth(f)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s: %v", redactURI(f), err))
				continue
			}
			rows = append(rows, OTPRow{Name: otpName(t, ""), TOTP: t})
		}
		if len(rows) == 0 && len(failed) == 0 {
			return nil, nil, errors.New("no 2FA secrets found in this file")
		}
		return rows, failed, nil
	}
	decrypted := 0
	for _, tok := range tokens {
		label := firstOf(tok, "name", "original_name", "issuer")
		seed, encrypted := tok["decrypted_seed"], tok["decrypted_seed"] == ""
		if encrypted {
			if seed, err = decryptAuthy(tok, authyPassword); err != nil {
				failed = append(failed, label)
				continue
			}
		}
		secret, err := seedBytes(seed)
		if err != nil {
			// A wrong password can still pass the padding check now and then; the seed is garbage then.
			failed = append(failed, label)
			continue
		}
		if encrypted {
			decrypted++
		}
		t := vault.TOTP{Secret: secret, Algorithm: "SHA1", Digits: 6, Period: 30, Issuer: strings.TrimSpace(tok["issuer"])}
		if d, err := strconv.Atoi(tok["digits"]); err == nil && d >= 6 && d <= 10 {
			t.Digits = d
		}
		name := strings.TrimSpace(tok["name"])
		if issuer, account, ok := strings.Cut(name, ":"); ok {
			if t.Issuer == "" {
				t.Issuer = strings.TrimSpace(issuer)
			}
			t.Account = strings.TrimSpace(account)
		} else if !strings.EqualFold(name, t.Issuer) {
			t.Account = name
		}
		rows = append(rows, OTPRow{Name: otpName(t, name), TOTP: t})
	}
	if kind == KindAuthy && decrypted == 0 && len(failed) > 0 {
		return nil, failed, ErrWrongPassword
	}
	return rows, failed, nil
}

// authyTokens finds Authy token objects (anything with an encrypted_seed or decrypted_seed) in JSON of any shape
// ({"authenticator_tokens": [...]}, a bare list, or nested deeper), or in a CSV with those columns.
func authyTokens(data []byte) []map[string]string {
	var tokens []map[string]string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			if _, ok := x["encrypted_seed"]; !ok {
				if _, ok := x["decrypted_seed"]; !ok {
					for _, e := range x {
						walk(e)
					}
					return
				}
			}
			tok := map[string]string{}
			for k, e := range x {
				switch y := e.(type) {
				case string:
					tok[k] = y
				case float64:
					tok[k] = strconv.FormatFloat(y, 'f', -1, 64)
				}
			}
			tokens = append(tokens, tok)
		}
	}
	var v any
	if json.Unmarshal(data, &v) == nil {
		walk(v)
		return tokens
	}
	recs, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil || len(recs) < 2 {
		return nil
	}
	header := recs[0]
	if !slices.Contains(header, "encrypted_seed") && !slices.Contains(header, "decrypted_seed") {
		return nil
	}
	for _, r := range recs[1:] {
		tok := map[string]string{}
		for i, h := range header {
			if i < len(r) {
				tok[strings.TrimSpace(h)] = r[i]
			}
		}
		tokens = append(tokens, tok)
	}
	return tokens
}

// decryptAuthy undoes Authy's backup encryption: AES-256-CBC with a PBKDF2-HMAC-SHA1 key from the backup password
// and the token's salt (as text), key_derivation_iterations rounds (1000 on old tokens), and the hex unique_iv or,
// on old tokens, a zero IV.
func decryptAuthy(tok map[string]string, password string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tok["encrypted_seed"]))
	if err != nil || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return "", errors.New("encrypted_seed is not valid")
	}
	rounds := 1000
	if n, err := strconv.Atoi(tok["key_derivation_iterations"]); err == nil && n > 0 {
		rounds = n
	}
	key, err := pbkdf2.Key(sha1.New, password, []byte(tok["salt"]), rounds, 32)
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if s := strings.TrimSpace(tok["unique_iv"]); s != "" {
		if iv, err = hex.DecodeString(s); err != nil || len(iv) != aes.BlockSize {
			return "", errors.New("unique_iv is not valid")
		}
	}
	block, _ := aes.NewCipher(key)
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	n := int(pt[len(pt)-1])
	if n == 0 || n > aes.BlockSize || !bytes.Equal(pt[len(pt)-n:], bytes.Repeat([]byte{byte(n)}, n)) {
		return "", errors.New("wrong password")
	}
	return string(pt[:len(pt)-n]), nil
}

// seedBytes reads a decrypted seed: base32 as a rule, hex for some Authy tokens.
func seedBytes(seed string) ([]byte, error) {
	seed = strings.TrimSpace(seed)
	if b, err := vault.DecodeBase32(seed); err == nil {
		return b, nil
	}
	if b, err := hex.DecodeString(seed); err == nil && len(b) > 0 {
		return b, nil
	}
	return nil, errors.New("the secret is neither base32 nor hex")
}

func otpName(t vault.TOTP, fallback string) string {
	switch {
	case t.Issuer != "":
		return t.Issuer
	case fallback != "":
		return fallback
	case t.Account != "":
		return t.Account
	}
	return "2FA code"
}

func firstOf(m map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(m[k]); v != "" {
			return v
		}
	}
	return "a token without a name"
}

// redactURI keeps an otpauth:// URI's label for error messages but drops its secret.
func redactURI(u string) string {
	if i := strings.Index(u, "?"); i >= 0 {
		return u[:i]
	}
	return u
}

// BuildOTP matches 2FA secrets against the vault: one already saved (same secret) is skipped, the others become
// 2FA secrets linked to an existing context whose name or website fits the issuer (GitHub → github.com).
func BuildOTP(existing map[string]vault.Item, rows []OTPRow, newID func() string, now time.Time) Plan {
	now = now.UTC().Truncate(time.Second)
	items := make(map[string]vault.Item, len(existing))
	for id, it := range existing {
		items[id] = it
	}
	plan := Plan{Writes: map[string]vault.Item{}}
	for _, r := range rows {
		secret := r.TOTP.Fields()[vault.FieldSecret]
		line := Line{Name: r.Name}
		if r.TOTP.Account != "" {
			line.Site = r.TOTP.Account
		}
		dup := ""
		for _, id := range sortedIDs(items) {
			it := items[id]
			if it.Kind == vault.KindSecret && it.Type == vault.TypeTOTP {
				if t, err := vault.TOTPFromFields(it.Fields); err == nil && t.Fields()[vault.FieldSecret] == secret {
					dup = id
					break
				}
			}
		}
		if dup != "" {
			line.Action, line.ID = Skip, dup
			plan.Lines = append(plan.Lines, line)
			continue
		}
		it := vault.Item{Kind: vault.KindSecret, Type: vault.TypeTOTP, Name: r.Name, Fields: r.TOTP.Fields(),
			CreatedAt: now, UpdatedAt: now}
		if c := contextForIssuer(items, r.TOTP.Issuer, r.Name); c != "" {
			it.Contexts = []string{c}
		}
		id := newID()
		items[id] = it
		plan.Writes[id] = it
		line.Action, line.ID = Add, id
		plan.Lines = append(plan.Lines, line)
	}
	return plan
}

// contextForIssuer finds the context an issuer belongs to: the same name, or a website whose host starts with the
// issuer without spaces and punctuation ("GitHub" → github.com). Anything less certain is left unlinked.
func contextForIssuer(items map[string]vault.Item, names ...string) string {
	norm := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	for _, n := range names {
		want := norm(n)
		if want == "" {
			continue
		}
		for _, id := range sortedIDs(items) {
			c := items[id]
			if c.Kind != vault.KindContext {
				continue
			}
			if norm(c.Name) == want {
				return id
			}
			for _, u := range c.URLs {
				h := vault.Host(u)
				if label, _, _ := strings.Cut(h, "."); label != "" && norm(label) == want {
					return id
				}
			}
		}
	}
	return ""
}
