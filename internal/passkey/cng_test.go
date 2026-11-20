package passkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"
)

func ecBlob(pub *ecdsa.PublicKey, magic uint32) []byte {
	n := (pub.Curve.Params().BitSize + 7) / 8
	b := binary.LittleEndian.AppendUint32(nil, magic)
	b = binary.LittleEndian.AppendUint32(b, uint32(n))
	return append(append(b, pub.X.FillBytes(make([]byte, n))...), pub.Y.FillBytes(make([]byte, n))...)
}

func TestVerifyCNGECDSA(t *testing.T) {
	for _, c := range []struct {
		curve elliptic.Curve
		magic uint32
	}{{elliptic.P256(), cngECDSAP256}, {elliptic.P384(), cngECDSAP384}, {elliptic.P521(), cngECDSAP521}} {
		k, _ := ecdsa.GenerateKey(c.curve, rand.Reader)
		data := []byte("encoded request")
		d := sha256.Sum256(data)
		r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
		n := (c.curve.Params().BitSize + 7) / 8
		sig := append(r.FillBytes(make([]byte, n)), s.FillBytes(make([]byte, n))...)
		blob := ecBlob(&k.PublicKey, c.magic)
		if err := VerifyCNG(blob, data, sig); err != nil {
			t.Fatalf("%s: %v", c.curve.Params().Name, err)
		}
		if VerifyCNG(blob, []byte("other request"), sig) == nil {
			t.Fatalf("%s: accepted a signature over other data", c.curve.Params().Name)
		}
		if VerifyCNG(blob, data, sig[1:]) == nil || VerifyCNG(blob[:len(blob)-1], data, sig) == nil {
			t.Fatal("accepted a truncated signature or key")
		}
	}
}

func TestVerifyCNGRSA(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := []byte("encoded request")
	d := sha256.Sum256(data)
	sig, _ := rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: 32})
	e := big.NewInt(int64(k.E)).Bytes()
	m := k.N.Bytes()
	b := binary.LittleEndian.AppendUint32(nil, cngRSAPublic)
	for _, v := range []int{k.N.BitLen(), len(e), len(m), 0, 0} {
		b = binary.LittleEndian.AppendUint32(b, uint32(v))
	}
	b = append(append(b, e...), m...)
	if err := VerifyCNG(b, data, sig); err != nil {
		t.Fatal(err)
	}
	if VerifyCNG(b, []byte("x"), sig) == nil {
		t.Fatal("accepted a signature over other data")
	}
	if VerifyCNG([]byte{1, 2, 3, 4, 5, 6, 7, 8}, data, sig) == nil {
		t.Fatal("accepted an unknown key type")
	}
}
