package passkey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type vectors struct {
	Passkey           map[string]string `json:"passkey"`
	PublicKey         string            `json:"public_key"`
	ClientDataJSON    string            `json:"client_data_json"`
	AuthenticatorData string            `json:"authenticator_data"`
}

func load(t *testing.T) vectors {
	raw, err := os.ReadFile("../../testdata/passkey.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func verify(t *testing.T, spki, authData, cdHash, sig []byte) {
	t.Helper()
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(append(append([]byte{}, authData...), cdHash...))
	if !ecdsa.VerifyASN1(k.(*ecdsa.PublicKey), d[:], sig) {
		t.Fatal("signature does not verify")
	}
}

func TestAssertSharedVector(t *testing.T) {
	v := load(t)
	cd, _ := Unb64(v.ClientDataJSON)
	h := sha256.Sum256(cd)
	a, err := Assert(v.Passkey, h[:])
	if err != nil {
		t.Fatal(err)
	}
	if B64(a.AuthenticatorData) != v.AuthenticatorData {
		t.Fatalf("authenticator data %s, want %s", B64(a.AuthenticatorData), v.AuthenticatorData)
	}
	if B64(a.CredentialID) != v.Passkey[FieldCredentialID] || B64(a.UserHandle) != v.Passkey[FieldUserHandle] {
		t.Fatal("wrong credential id or user handle")
	}
	spki, _ := Unb64(v.PublicKey)
	verify(t, spki, a.AuthenticatorData, h[:], a.Signature)
	if _, err := Assert(v.Passkey, h[:5]); err == nil {
		t.Fatal("short hash accepted")
	}
}

func TestCreateThenAssert(t *testing.T) {
	c, err := Create("example.com", User{ID: []byte{7, 7, 7}, Name: "me@example.com", DisplayName: "Me"})
	if err != nil {
		t.Fatal(err)
	}
	ad := c.AuthenticatorData
	rp := sha256.Sum256([]byte("example.com"))
	if !bytes.Equal(ad[:32], rp[:]) || ad[32] != 0x5d || !bytes.Equal(ad[37:53], AAGUID[:]) {
		t.Fatalf("bad authenticator data %x", ad)
	}
	if n := int(ad[53])<<8 | int(ad[54]); n != 16 || !bytes.Equal(ad[55:71], c.CredentialID) {
		t.Fatal("bad credential id in authenticator data")
	}
	// The COSE key matches the SPKI public key.
	k, _ := x509.ParsePKIXPublicKey(c.PublicKey)
	raw, _ := k.(*ecdsa.PublicKey).Bytes()
	if !bytes.Contains(ad[71:], raw[1:33]) || !bytes.Contains(ad[71:], raw[33:]) {
		t.Fatal("COSE key does not match")
	}
	if !bytes.HasPrefix(c.AttestationObject, []byte{0xa3, 0x63, 'f', 'm', 't', 0x64, 'n', 'o', 'n', 'e'}) {
		t.Fatalf("bad attestation object %x", c.AttestationObject[:12])
	}
	if c.Fields[FieldUserHandle] != "BwcH" || c.Fields[FieldRPID] != "example.com" {
		t.Fatalf("fields %v", c.Fields)
	}
	h := sha256.Sum256([]byte("{}"))
	a, err := Assert(c.Fields, h[:])
	if err != nil {
		t.Fatal(err)
	}
	verify(t, c.PublicKey, a.AuthenticatorData, h[:], a.Signature)
}

func TestSave(t *testing.T) {
	now := time.Now()
	f := map[string]string{FieldRPID: "example.com"}
	if w := Save("", f, func(string) string { return "ctx" }, now); len(w) != 1 {
		t.Fatal("context made though one exists")
	}
	w := Save("Example", f, func(string) string { return "" }, now)
	if len(w) != 2 {
		t.Fatal("no new context")
	}
	for _, it := range w {
		if it.Kind == "context" && (it.URLs[0] != "https://example.com" || it.ContextType != "website") {
			t.Fatalf("context %+v", it)
		}
	}
}

func TestAuthenticatorInfo(t *testing.T) {
	// The same bytes as Microsoft's sample minus its prf/hmac-secret extensions (key 2), with storii's AAGUID.
	want := "A50182684649444F5F325F30684649444F5F325F310350D1A8C0B05F2E4C3B9A7E73746F72696904A362726BF5627570F5627576F5098168696E7465726E616C0A81A263616C672664747970656A7075626C69632D6B6579"
	got := ""
	for _, b := range AuthenticatorInfo() {
		got += string("0123456789ABCDEF"[b>>4]) + string("0123456789ABCDEF"[b&15])
	}
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}
