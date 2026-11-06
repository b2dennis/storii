package vault

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

const vectorsPath = "../../testdata/vectors.json"

// Vectors is the format of testdata/vectors.json, shared by every client's tests.
type Vectors struct {
	Comment string `json:"comment"`
	KDF     []struct {
		Comment  string `json:"comment,omitempty"`
		Password string `json:"password"`
		KDF      KDF    `json:"kdf"`
		AuthKey  string `json:"auth_key"`
		WrapKey  string `json:"wrap_key"`
	} `json:"kdf"`
	VaultKey struct {
		WrapKey  string `json:"wrap_key"`
		VaultKey string `json:"vault_key"`
		Nonce    string `json:"nonce"`
		Wrapped  string `json:"wrapped"`
	} `json:"vault_key"`
	Items []struct {
		ID        string `json:"id"`
		VaultKey  string `json:"vault_key"`
		Nonce     string `json:"nonce"`
		Plaintext string `json:"plaintext"`
		Data      string `json:"data"`
	} `json:"items"`
	TOTP []struct {
		Fields map[string]string `json:"fields"`
		Time   int64             `json:"time"`
		Code   string            `json:"code"`
	} `json:"totp"`
	OTPAuth []struct {
		URI    string            `json:"uri"`
		Fields map[string]string `json:"fields,omitempty"`
		Error  bool              `json:"error,omitempty"`
	} `json:"otpauth"`
	Match []struct {
		ContextURL string `json:"context_url"`
		Host       string `json:"host"`
		Match      bool   `json:"match"`
	} `json:"match"`
}

func dec(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if *update {
		fillVectors(t, &v)
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for _, k := range v.KDF {
		keys, err := DeriveKeys(k.Password, k.KDF)
		if err != nil {
			t.Fatal(err)
		}
		if keys.AuthKey() != k.AuthKey || b64(keys.Wrap) != k.WrapKey {
			t.Errorf("kdf %q: got auth %s wrap %s", k.Password, keys.AuthKey(), b64(keys.Wrap))
		}
	}

	vk := v.VaultKey
	if got, _ := seal(dec(t, vk.WrapKey), dec(t, vk.VaultKey), aadVaultKey, dec(t, vk.Nonce)); got != vk.Wrapped {
		t.Errorf("wrapped vault key: got %s", got)
	}
	if key, err := UnwrapVaultKey(dec(t, vk.WrapKey), vk.Wrapped); err != nil || b64(key) != vk.VaultKey {
		t.Errorf("unwrap: %v", err)
	}

	for _, it := range v.Items {
		key := dec(t, it.VaultKey)
		if got, _ := seal(key, []byte(it.Plaintext), aadItemPrefix+it.ID, dec(t, it.Nonce)); got != it.Data {
			t.Errorf("item %s: got %s", it.ID, got)
		}
		pt, err := DecryptItem(key, it.ID, it.Data)
		if err != nil || string(pt) != it.Plaintext {
			t.Errorf("decrypt item %s: %v", it.ID, err)
		}
		if _, err := DecryptItem(key, "00000000-0000-0000-0000-000000000000", it.Data); err == nil {
			t.Errorf("item %s decrypted under another id", it.ID)
		}
		if _, err := UnmarshalItem(pt); err != nil {
			t.Errorf("item %s: %v", it.ID, err)
		}
	}

	for _, c := range v.TOTP {
		totp, err := TOTPFromFields(c.Fields)
		if err != nil {
			t.Fatal(err)
		}
		if got := totp.Code(time.Unix(c.Time, 0)); got != c.Code {
			t.Errorf("totp %v at %d: got %s want %s", c.Fields, c.Time, got, c.Code)
		}
	}

	for _, c := range v.OTPAuth {
		totp, err := ParseOTPAuth(c.URI)
		if c.Error {
			if err == nil {
				t.Errorf("%s: expected an error", c.URI)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.URI, err)
			continue
		}
		got, _ := json.Marshal(totp.Fields())
		want, _ := json.Marshal(c.Fields)
		if string(got) != string(want) {
			t.Errorf("%s: got %s want %s", c.URI, got, want)
		}
	}

	for _, c := range v.Match {
		if got := MatchesHost(c.ContextURL, c.Host); got != c.Match {
			t.Errorf("match %q on %q: got %v", c.ContextURL, c.Host, got)
		}
	}
}

// fillVectors computes the outputs for the inputs in the file (go test ./internal/vault -update).
func fillVectors(t *testing.T, v *Vectors) {
	for i := range v.KDF {
		keys, err := DeriveKeys(v.KDF[i].Password, v.KDF[i].KDF)
		if err != nil {
			t.Fatal(err)
		}
		v.KDF[i].AuthKey, v.KDF[i].WrapKey = keys.AuthKey(), b64(keys.Wrap)
	}
	v.VaultKey.WrapKey = v.KDF[0].WrapKey
	v.VaultKey.Wrapped, _ = seal(dec(t, v.VaultKey.WrapKey), dec(t, v.VaultKey.VaultKey), aadVaultKey, dec(t, v.VaultKey.Nonce))
	for i := range v.Items {
		it := &v.Items[i]
		it.VaultKey = v.VaultKey.VaultKey
		it.Data, _ = seal(dec(t, it.VaultKey), []byte(it.Plaintext), aadItemPrefix+it.ID, dec(t, it.Nonce))
	}
	for i := range v.TOTP {
		totp, err := TOTPFromFields(v.TOTP[i].Fields)
		if err != nil {
			t.Fatal(err)
		}
		if v.TOTP[i].Code == "" {
			v.TOTP[i].Code = totp.Code(time.Unix(v.TOTP[i].Time, 0))
		}
	}
}

func TestRoundTrip(t *testing.T) {
	kdf := NewKDF()
	kdf.MemoryKiB = 16 * 1024 // keep the test quick
	keys, err := DeriveKeys("correct horse", kdf)
	if err != nil {
		t.Fatal(err)
	}
	vk := NewVaultKey()
	wrapped, _ := WrapVaultKey(keys.Wrap, vk)
	other, _ := DeriveKeys("wrong horse", kdf)
	if _, err := UnwrapVaultKey(other.Wrap, wrapped); err != ErrDecrypt {
		t.Fatal("wrong password unwrapped the vault key")
	}
	got, err := UnwrapVaultKey(keys.Wrap, wrapped)
	if err != nil || string(got) != string(vk) {
		t.Fatal("unwrap failed", err)
	}
	data, _ := EncryptItem(vk, "a", []byte("hello"))
	if pt, err := DecryptItem(vk, "a", data); err != nil || string(pt) != "hello" {
		t.Fatal(err)
	}
	if _, err := DecryptItem(vk, "b", data); err == nil {
		t.Fatal("decrypted with a different id")
	}
}

func TestOTPAuthRoundTrip(t *testing.T) {
	totp, err := ParseOTPAuth("otpauth://totp/ACME%20Co:john@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&period=60&digits=8&algorithm=SHA256")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ParseOTPAuth(totp.URI())
	if err != nil || again.URI() != totp.URI() {
		t.Fatalf("%v %s", err, totp.URI())
	}
}

func TestGeneratePassword(t *testing.T) {
	for range 50 {
		p := GeneratePassword(16, true)
		if len(p) != 16 || !strings.ContainsAny(p, symbols) || !strings.ContainsAny(p, digits) {
			t.Fatal(p)
		}
	}
}
