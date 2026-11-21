package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

// testdata/sharing.json pins the sharing crypto for every client (the Go test rewrites it with -update).
type shareVector struct {
	Comment          string          `json:"comment"`
	VaultKey         string          `json:"vault_key"`
	PrivateKey       string          `json:"private_key"`
	PublicKey        string          `json:"public_key"`
	SealedPrivateKey string          `json:"sealed_private_key"` // nonce 12 × 0x01
	Fingerprint      string          `json:"fingerprint"`
	ShareID          string          `json:"share_id"`
	ShareKey         string          `json:"share_key"`
	EphemeralKey     string          `json:"ephemeral_private_key"`
	WrappedKey       string          `json:"wrapped_key"` // nonce 12 × 0x02
	Meta             ShareMeta       `json:"meta"`
	MetaData         string          `json:"meta_data"` // nonce 12 × 0x03
	ItemID           string          `json:"item_id"`
	Item             json.RawMessage `json:"item"`
	ItemData         string          `json:"item_data"` // nonce 12 × 0x04
}

func unb64(t *testing.T, s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestShareVector(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/sharing.json")
	if err != nil {
		t.Fatal(err)
	}
	var v shareVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer // the plaintext is the item's compact JSON
	if err := json.Compact(&compact, v.Item); err != nil {
		t.Fatal(err)
	}
	v.Item = compact.Bytes()
	vk, priv, sk, eph := unb64(t, v.VaultKey), unb64(t, v.PrivateKey), unb64(t, v.ShareKey), unb64(t, v.EphemeralKey)
	pub, err := PublicKeyOf(priv)
	if err != nil {
		t.Fatal(err)
	}
	n := func(b byte) []byte { return bytes.Repeat([]byte{b}, 12) }
	if *update {
		v.PublicKey = b64(pub)
		v.SealedPrivateKey, _ = seal(vk, priv, aadSharePrivate, n(1))
		v.Fingerprint = Fingerprint(pub)
		v.WrappedKey, _ = WrapShareKey(pub, v.ShareID, sk, eph, n(2))
		v.MetaData, _ = SealShareMeta(sk, v.ShareID, v.Meta, n(3))
		v.ItemData, _ = EncryptShareItem(sk, v.ShareID, v.ItemID, v.Item, n(4))
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile("../../testdata/sharing.json", append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if b64(pub) != v.PublicKey || Fingerprint(pub) != v.Fingerprint {
		t.Fatalf("public key %s / %s", b64(pub), Fingerprint(pub))
	}
	if got, err := OpenSharePrivateKey(vk, v.SealedPrivateKey); err != nil || !bytes.Equal(got, priv) {
		t.Fatalf("private key: %v", err)
	}
	if w, _ := WrapShareKey(pub, v.ShareID, sk, eph, n(2)); w != v.WrappedKey {
		t.Fatalf("wrapped %s", w)
	}
	if got, err := UnwrapShareKey(priv, v.ShareID, v.WrappedKey); err != nil || !bytes.Equal(got, sk) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := UnwrapShareKey(priv, "00000000-0000-0000-0000-000000000000", v.WrappedKey); err != ErrDecrypt {
		t.Fatal("a wrapped key opened for another share")
	}
	if m, err := OpenShareMeta(sk, v.ShareID, v.MetaData); err != nil || m != v.Meta {
		t.Fatalf("meta: %v %v", m, err)
	}
	if pt, err := DecryptShareItem(sk, v.ShareID, v.ItemID, v.ItemData); err != nil || !bytes.Equal(pt, v.Item) {
		t.Fatalf("item: %s %v", pt, err)
	}
	if _, err := DecryptItem(sk, v.ItemID, v.ItemData); err != ErrDecrypt {
		t.Fatal("a share item opened as a personal item")
	}
	// Fresh keys round-trip.
	p2, pub2 := NewShareKeyPair()
	w, err := WrapShareKey(pub2, v.ShareID, sk, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := UnwrapShareKey(p2, v.ShareID, w); err != nil || !bytes.Equal(got, sk) {
		t.Fatal(err)
	}
	if _, err := UnwrapShareKey(priv, v.ShareID, w); err != ErrDecrypt {
		t.Fatal("someone else's key unwrapped it")
	}
}
