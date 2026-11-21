package vault

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// Sharing (docs/CRYPTO.md#sharing). Every account has an X25519 key pair: the public key is on the server, the private
// key is sealed with the vault key. A share has its own random key, wrapped for each member's public key; its name and
// items are sealed with that key.

const (
	aadSharePrivate = "storii:share-private-key"
	infoShareWrap   = "storii share key"
)

// NewShareKeyPair returns a fresh X25519 key pair (32 bytes each).
func NewShareKeyPair() (priv, pub []byte) {
	k, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		panic(err) // only fails if the system's randomness does
	}
	return k.Bytes(), k.PublicKey().Bytes()
}

// SealSharePrivateKey keeps the account's private key with the vault key, the same way on every device.
func SealSharePrivateKey(vaultKey, priv []byte) (string, error) {
	return seal(vaultKey, priv, aadSharePrivate, nil)
}

func OpenSharePrivateKey(vaultKey []byte, sealed string) ([]byte, error) {
	k, err := open(vaultKey, sealed, aadSharePrivate)
	if err == nil && len(k) != keyLen {
		return nil, ErrDecrypt
	}
	return k, err
}

// PublicKeyOf derives the public key from a private key.
func PublicKeyOf(priv []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, ErrDecrypt
	}
	return k.PublicKey().Bytes(), nil
}

// Fingerprint is what two people compare (in person, or over another channel) to make sure the server handed out the
// right public key: the first 16 bytes of its SHA-256, as 8 groups of 4 hex digits.
func Fingerprint(pub []byte) string {
	h := sha256.Sum256(pub)
	s := hex.EncodeToString(h[:16])
	var groups []string
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:i+4])
	}
	return strings.Join(groups, " ")
}

func NewShareKey() []byte { return randomBytes(keyLen) }

func shareWrapKey(shared, ephPub, recipientPub []byte) ([]byte, error) {
	ikm := append(append(append([]byte{}, shared...), ephPub...), recipientPub...)
	return hkdf.Key(sha256.New, ikm, nil, infoShareWrap, keyLen)
}

// WrapShareKey encrypts a share's key for one member: "base64(ephemeral public key).envelope". eph is the ephemeral
// private key; nil means a fresh one (tests pin it).
func WrapShareKey(recipientPub []byte, shareID string, shareKey, eph, nonce []byte) (string, error) {
	curve := ecdh.X25519()
	r, err := curve.NewPublicKey(recipientPub)
	if err != nil {
		return "", ErrDecrypt
	}
	var e *ecdh.PrivateKey
	if eph == nil {
		e, err = curve.GenerateKey(nil)
	} else {
		e, err = curve.NewPrivateKey(eph)
	}
	if err != nil {
		return "", err
	}
	shared, err := e.ECDH(r) // fails on low-order points
	if err != nil {
		return "", ErrDecrypt
	}
	ephPub := e.PublicKey().Bytes()
	key, err := shareWrapKey(shared, ephPub, recipientPub)
	if err != nil {
		return "", err
	}
	env, err := seal(key, shareKey, "storii:share-key:"+shareID, nonce)
	return b64(ephPub) + "." + env, err
}

// UnwrapShareKey opens a share's key with the member's private key.
func UnwrapShareKey(priv []byte, shareID, wrapped string) ([]byte, error) {
	ephB64, env, ok := strings.Cut(wrapped, ".")
	ephPub, err := base64.StdEncoding.DecodeString(ephB64)
	if !ok || err != nil {
		return nil, ErrDecrypt
	}
	curve := ecdh.X25519()
	k, err := curve.NewPrivateKey(priv)
	if err != nil {
		return nil, ErrDecrypt
	}
	e, err := curve.NewPublicKey(ephPub)
	if err != nil {
		return nil, ErrDecrypt
	}
	shared, err := k.ECDH(e)
	if err != nil {
		return nil, ErrDecrypt
	}
	key, err := shareWrapKey(shared, ephPub, k.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	sk, err := open(key, env, "storii:share-key:"+shareID)
	if err == nil && len(sk) != keyLen {
		return nil, ErrDecrypt
	}
	return sk, err
}

// ShareMeta is a share's encrypted description.
type ShareMeta struct {
	Name string `json:"name"`
}

func SealShareMeta(shareKey []byte, shareID string, m ShareMeta, nonce []byte) (string, error) {
	raw, _ := json.Marshal(m)
	return seal(shareKey, raw, "storii:share:"+shareID, nonce)
}

func OpenShareMeta(shareKey []byte, shareID, data string) (ShareMeta, error) {
	var m ShareMeta
	raw, err := open(shareKey, data, "storii:share:"+shareID)
	if err == nil {
		err = json.Unmarshal(raw, &m)
	}
	return m, err
}

// EncryptShareItem seals an item kept in a share. Both ids are bound, so the server can't move items between shares
// or into someone's own vault.
func EncryptShareItem(shareKey []byte, shareID, id string, plaintext, nonce []byte) (string, error) {
	return seal(shareKey, plaintext, "storii:share:"+shareID+":item:"+id, nonce)
}

func DecryptShareItem(shareKey []byte, shareID, id, data string) ([]byte, error) {
	return open(shareKey, data, "storii:share:"+shareID+":item:"+id)
}
