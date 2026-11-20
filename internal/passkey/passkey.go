// Package passkey is storii's WebAuthn authenticator in Go, as the extension's src/lib/passkey.js: an ES256 key pair
// per credential, attestation "none", backed up and synced (BE and BS flags set, sign count 0). The Windows tray uses
// it as a plugin authenticator; Windows builds clientDataJSON itself and hands over only its hash.
package passkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/b2dennis/storii/internal/vault"
)

// Passkey item fields (see vault.TypePasskey).
const (
	FieldCredentialID    = "credential_id"
	FieldRPID            = "rp_id"
	FieldUserHandle      = "user_handle"
	FieldUserName        = "user_name"
	FieldUserDisplayName = "user_display_name"
	FieldPrivateKey      = "private_key"
)

// AAGUID is storii's authenticator id (the bytes end in "storii").
var AAGUID = [16]byte{0xd1, 0xa8, 0xc0, 0xb0, 0x5f, 0x2e, 0x4c, 0x3b, 0x9a, 0x7e, 0x73, 0x74, 0x6f, 0x72, 0x69, 0x69}

const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
	flags  = flagUP | flagUV | flagBE | flagBS
)

var b64 = base64.RawURLEncoding

// B64 and Unb64 are base64url without padding, as the passkey fields store bytes.
func B64(b []byte) string { return b64.EncodeToString(b) }

func Unb64(s string) ([]byte, error) {
	s = strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(s, "="))
	return b64.DecodeString(s)
}

// User is the account a new passkey is for, as the site names it.
type User struct {
	ID          []byte
	Name        string
	DisplayName string
}

// Created is a new passkey: the fields to store and what the authenticator answers.
type Created struct {
	Fields            map[string]string
	CredentialID      []byte
	AuthenticatorData []byte // with the attested credential (AAGUID, credential id, COSE public key)
	AttestationObject []byte // fmt "none"
	PublicKey         []byte // SPKI
}

// Create makes a passkey for rpID.
func Create(rpID string, user User) (Created, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return Created{}, err
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		return Created{}, err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return Created{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return Created{}, err
	}
	raw, err := key.PublicKey.Bytes() // 0x04 | x | y
	if err != nil {
		return Created{}, err
	}
	cose := cborMap(
		cborInt(1), cborInt(2), // kty: EC2
		cborInt(3), cborInt(-7), // alg: ES256
		cborInt(-1), cborInt(1), // crv: P-256
		cborInt(-2), cborBytes(raw[1:33]),
		cborInt(-3), cborBytes(raw[33:65]),
	)
	ad := rpHash(rpID)
	ad = append(ad, flags|flagAT, 0, 0, 0, 0)
	ad = append(ad, AAGUID[:]...)
	ad = append(ad, byte(len(credID)>>8), byte(len(credID)))
	ad = append(ad, credID...)
	ad = append(ad, cose...)
	att := cborMap(
		cborText("fmt"), cborText("none"),
		cborText("attStmt"), cborMap(),
		cborText("authData"), cborBytes(ad),
	)
	return Created{
		Fields: map[string]string{
			FieldCredentialID: B64(credID), FieldRPID: rpID, FieldUserHandle: B64(user.ID), FieldUserName: user.Name,
			FieldUserDisplayName: user.DisplayName, FieldPrivateKey: B64(pkcs8),
		},
		CredentialID: credID, AuthenticatorData: ad, AttestationObject: att, PublicKey: spki,
	}, nil
}

// Assertion is a sign-in with a stored passkey.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte // DER ECDSA over authenticatorData || clientDataHash
	UserHandle        []byte
}

// Assert signs in with the passkey in fields. clientDataHash is SHA-256 of the clientDataJSON.
func Assert(fields map[string]string, clientDataHash []byte) (Assertion, error) {
	if len(clientDataHash) != sha256.Size {
		return Assertion{}, errors.New("passkey: client data hash must be 32 bytes")
	}
	credID, err := Unb64(fields[FieldCredentialID])
	if err != nil || len(credID) == 0 {
		return Assertion{}, errors.New("passkey: bad credential id")
	}
	der, err := Unb64(fields[FieldPrivateKey])
	if err != nil {
		return Assertion{}, errors.New("passkey: bad private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return Assertion{}, errors.New("passkey: bad private key")
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return Assertion{}, errors.New("passkey: not a P-256 key")
	}
	var handle []byte
	if h := fields[FieldUserHandle]; h != "" {
		if handle, err = Unb64(h); err != nil {
			return Assertion{}, errors.New("passkey: bad user handle")
		}
	}
	ad := append(rpHash(fields[FieldRPID]), flags, 0, 0, 0, 0)
	digest := sha256.Sum256(append(append([]byte{}, ad...), clientDataHash...))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return Assertion{}, err
	}
	return Assertion{CredentialID: credID, AuthenticatorData: ad, Signature: sig, UserHandle: handle}, nil
}

// Item is the vault item for a new passkey, in the website context ctxID.
func Item(name, ctxID string, fields map[string]string, now time.Time) vault.Item {
	if name == "" {
		name = fields[FieldRPID]
	}
	return vault.Item{Kind: vault.KindSecret, Type: vault.TypePasskey, Name: name, Contexts: []string{ctxID}, Fields: fields,
		CreatedAt: now, UpdatedAt: now}
}

// Save adds a new passkey to items' writes: the passkey and, when no context matches rpID yet, a website context for
// it. It returns the items to write. findContext returns the id of the context for a host, or "".
func Save(name string, fields map[string]string, findContext func(host string) string, now time.Time) map[string]vault.Item {
	out := map[string]vault.Item{}
	rp := fields[FieldRPID]
	ctx := findContext(rp)
	if ctx == "" {
		ctx = uuid.NewString()
		out[ctx] = vault.Item{Kind: vault.KindContext, Name: rp, ContextType: vault.ContextWebsite, URLs: []string{"https://" + rp},
			CreatedAt: now, UpdatedAt: now}
	}
	out[uuid.NewString()] = Item(name, ctx, fields, now)
	return out
}

func rpHash(rpID string) []byte {
	h := sha256.Sum256([]byte(rpID))
	return h[:]
}

// The CBOR WebAuthn needs: ints, byte and text strings, maps in the order given.
func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 1<<8:
		return []byte{major<<5 | 24, byte(n)}
	case n < 1<<16:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	default:
		return []byte{major<<5 | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
}

func cborInt(v int) []byte {
	if v >= 0 {
		return cborHead(0, uint64(v))
	}
	return cborHead(1, uint64(-1-v))
}

func cborBytes(b []byte) []byte { return append(cborHead(2, uint64(len(b))), b...) }
func cborText(s string) []byte  { return append(cborHead(3, uint64(len(s))), s...) }

// cborMap takes keys and values alternately, already encoded.
func cborMap(kv ...[]byte) []byte {
	out := cborHead(5, uint64(len(kv)/2))
	for _, p := range kv {
		out = append(out, p...)
	}
	return out
}

// AuthenticatorInfo is the CTAP2 authenticatorGetInfo response Windows asks for when the tray registers as a plugin:
// FIDO 2.0/2.1, storii's AAGUID, resident keys with user presence and verification, transport "internal", ES256.
func AuthenticatorInfo() []byte {
	return cborMap(
		cborInt(1), append(cborHead(4, 2), append(cborText("FIDO_2_0"), cborText("FIDO_2_1")...)...),
		cborInt(3), cborBytes(AAGUID[:]),
		cborInt(4), cborMap(cborText("rk"), []byte{0xf5}, cborText("up"), []byte{0xf5}, cborText("uv"), []byte{0xf5}),
		cborInt(9), append(cborHead(4, 1), cborText("internal")...),
		cborInt(10), append(cborHead(4, 1), cborMap(cborText("alg"), cborInt(-7), cborText("type"), cborText("public-key"))...),
	)
}
