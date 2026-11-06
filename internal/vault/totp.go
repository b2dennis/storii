package vault

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// TOTP holds RFC 6238 parameters.
type TOTP struct {
	Secret    []byte
	Algorithm string // SHA1, SHA256 or SHA512
	Digits    int
	Period    int
	Issuer    string
	Account   string
}

// DecodeBase32 accepts the usual sloppy forms: lowercase, spaces, dashes, missing padding.
func DecodeBase32(s string) ([]byte, error) {
	s = strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "=", "").Replace(s))
	b, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("TOTP secret is not valid base32")
	}
	return b, nil
}

// TOTPFromFields reads a totp secret's fields, applying the defaults (SHA1, 6 digits, 30 s).
func TOTPFromFields(f map[string]string) (TOTP, error) {
	secret, err := DecodeBase32(f[FieldSecret])
	if err != nil {
		return TOTP{}, err
	}
	t := TOTP{Secret: secret, Algorithm: "SHA1", Digits: 6, Period: 30, Issuer: f[FieldIssuer], Account: f[FieldAccount]}
	if a := strings.ToUpper(f[FieldAlgorithm]); a != "" {
		t.Algorithm = a
	}
	if d := f[FieldDigits]; d != "" {
		if t.Digits, err = strconv.Atoi(d); err != nil {
			return TOTP{}, errors.New("TOTP digits must be a number")
		}
	}
	if p := f[FieldPeriod]; p != "" {
		if t.Period, err = strconv.Atoi(p); err != nil {
			return TOTP{}, errors.New("TOTP period must be a number")
		}
	}
	return t, t.validate()
}

func (t TOTP) validate() error {
	switch {
	case t.Algorithm != "SHA1" && t.Algorithm != "SHA256" && t.Algorithm != "SHA512":
		return fmt.Errorf("unsupported TOTP algorithm %s", t.Algorithm)
	case t.Digits < 6 || t.Digits > 10:
		return errors.New("TOTP digits must be 6 to 10")
	case t.Period < 1 || t.Period > 300:
		return errors.New("TOTP period must be 1 to 300 seconds")
	}
	return nil
}

// Fields is the inverse of TOTPFromFields; defaults are left out.
func (t TOTP) Fields() map[string]string {
	f := map[string]string{FieldSecret: strings.TrimRight(base32.StdEncoding.EncodeToString(t.Secret), "=")}
	if t.Algorithm != "" && t.Algorithm != "SHA1" {
		f[FieldAlgorithm] = t.Algorithm
	}
	if t.Digits != 0 && t.Digits != 6 {
		f[FieldDigits] = strconv.Itoa(t.Digits)
	}
	if t.Period != 0 && t.Period != 30 {
		f[FieldPeriod] = strconv.Itoa(t.Period)
	}
	if t.Issuer != "" {
		f[FieldIssuer] = t.Issuer
	}
	if t.Account != "" {
		f[FieldAccount] = t.Account
	}
	return f
}

// Code returns the code for the time step containing now.
func (t TOTP) Code(now time.Time) string {
	return t.codeAt(uint64(now.Unix()) / uint64(t.Period))
}

// Remaining is how long the current code stays valid.
func (t TOTP) Remaining(now time.Time) time.Duration {
	p := int64(t.Period)
	return time.Duration(p-now.Unix()%p) * time.Second
}

func (t TOTP) codeAt(counter uint64) string {
	var h func() hash.Hash
	switch t.Algorithm {
	case "SHA256":
		h = sha256.New
	case "SHA512":
		h = sha512.New
	default:
		h = sha1.New
	}
	mac := hmac.New(h, t.Secret)
	binary.Write(mac, binary.BigEndian, counter)
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := uint64(binary.BigEndian.Uint32(sum[off:]) & 0x7fffffff)
	mod := uint64(1)
	for range t.Digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", t.Digits, v%mod)
}

// ParseOTPAuth reads an otpauth://totp/Issuer:account?secret=...&issuer=... URI (what 2FA QR codes contain).
func ParseOTPAuth(raw string) (TOTP, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "otpauth" {
		return TOTP{}, errors.New("not an otpauth:// URI")
	}
	if u.Host != "totp" {
		return TOTP{}, errors.New("only TOTP (time-based) codes are supported")
	}
	q := u.Query()
	f := map[string]string{FieldSecret: q.Get("secret"), FieldAlgorithm: q.Get("algorithm"),
		FieldDigits: q.Get("digits"), FieldPeriod: q.Get("period"), FieldIssuer: q.Get("issuer")}
	label := strings.TrimPrefix(u.Path, "/")
	if issuer, account, ok := strings.Cut(label, ":"); ok {
		if f[FieldIssuer] == "" {
			f[FieldIssuer] = strings.TrimSpace(issuer)
		}
		f[FieldAccount] = strings.TrimSpace(account)
	} else {
		f[FieldAccount] = label
	}
	return TOTPFromFields(f)
}

// URI formats t as an otpauth:// URI.
func (t TOTP) URI() string {
	label := t.Account
	if t.Issuer != "" {
		label = t.Issuer + ":" + t.Account
	}
	q := url.Values{}
	for k, v := range t.Fields() {
		if k != FieldAccount {
			q.Set(k, v)
		}
	}
	return (&url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + label, RawQuery: q.Encode()}).String()
}
