// Package vault holds everything a storii client needs that doesn't talk to the network: key derivation, item
// encryption, the item formats, TOTP codes and URL matching. docs/CRYPTO.md describes the format and
// testdata/vectors.json pins it for the other clients.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"
)

// KDF describes how the master key is derived from the master password. It is stored on the server in the clear.
type KDF struct {
	Alg         string `json:"alg"` // always "argon2id"
	Salt        string `json:"salt"`
	Iterations  uint32 `json:"iterations"`
	MemoryKiB   uint32 `json:"memory_kib"`
	Parallelism uint8  `json:"parallelism"`
}

// Same cost as storii v1, which every client already handled.
const (
	DefaultIterations  = 3
	DefaultMemoryKiB   = 64 * 1024
	DefaultParallelism = 2
)

const (
	formatVersion = 1
	keyLen        = 32
	nonceLen      = 12
	infoAuth      = "storii auth"
	infoWrap      = "storii wrap"
	aadVaultKey   = "storii:vault-key"
	aadItemPrefix = "storii:item:"
)

var ErrDecrypt = errors.New("decryption failed (wrong master password or corrupted data)")

// NewKDF returns default parameters with a fresh random salt.
func NewKDF() KDF {
	return KDF{Alg: "argon2id", Salt: b64(randomBytes(16)), Iterations: DefaultIterations,
		MemoryKiB: DefaultMemoryKiB, Parallelism: DefaultParallelism}
}

func (k KDF) Validate() error {
	salt, err := base64.StdEncoding.DecodeString(k.Salt)
	switch {
	case k.Alg != "argon2id":
		return fmt.Errorf("unsupported kdf %q", k.Alg)
	case err != nil || len(salt) < 16:
		return errors.New("kdf salt must be at least 16 bytes of base64")
	case k.Iterations < 1 || k.Iterations > 20:
		return errors.New("kdf iterations out of range")
	case k.MemoryKiB < 16*1024 || k.MemoryKiB > 1024*1024:
		return errors.New("kdf memory out of range")
	case k.Parallelism < 1 || k.Parallelism > 16:
		return errors.New("kdf parallelism out of range")
	}
	return nil
}

// Keys are derived from the master password. Auth goes to the server; Wrap never leaves the client.
type Keys struct {
	Auth []byte
	Wrap []byte
}

// DeriveKeys runs Argon2id (slow) over the NFC-normalized password and splits the result with HKDF-SHA256.
// Normalizing means the same password typed on different keyboards gives the same keys.
func DeriveKeys(password string, k KDF) (Keys, error) {
	if err := k.Validate(); err != nil {
		return Keys{}, err
	}
	salt, _ := base64.StdEncoding.DecodeString(k.Salt)
	master := argon2.IDKey([]byte(norm.NFC.String(password)), salt, k.Iterations, k.MemoryKiB, k.Parallelism, keyLen)
	auth, err := hkdf.Key(sha256.New, master, nil, infoAuth, keyLen)
	if err != nil {
		return Keys{}, err
	}
	wrap, err := hkdf.Key(sha256.New, master, nil, infoWrap, keyLen)
	if err != nil {
		return Keys{}, err
	}
	return Keys{Auth: auth, Wrap: wrap}, nil
}

// AuthKey is the base64 form the API expects.
func (k Keys) AuthKey() string { return b64(k.Auth) }

// NewVaultKey returns a random key for a new account.
func NewVaultKey() []byte { return randomBytes(keyLen) }

func WrapVaultKey(wrap, vaultKey []byte) (string, error) {
	return seal(wrap, vaultKey, aadVaultKey, nil)
}

func UnwrapVaultKey(wrap []byte, wrapped string) ([]byte, error) {
	key, err := open(wrap, wrapped, aadVaultKey)
	if err == nil && len(key) != keyLen {
		return nil, ErrDecrypt
	}
	return key, err
}

// EncryptItem seals an item's JSON. The id is bound as associated data, so the server can't swap blobs around.
func EncryptItem(vaultKey []byte, id string, plaintext []byte) (string, error) {
	return seal(vaultKey, plaintext, aadItemPrefix+id, nil)
}

func DecryptItem(vaultKey []byte, id, data string) ([]byte, error) {
	return open(vaultKey, data, aadItemPrefix+id)
}

// seal returns base64(version || nonce || ciphertext+tag). A nil nonce means a random one.
func seal(key, plaintext []byte, aad string, nonce []byte) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	if nonce == nil {
		nonce = randomBytes(nonceLen)
	}
	out := append([]byte{formatVersion}, nonce...)
	out = gcm.Seal(out, nonce, plaintext, []byte(aad))
	return b64(out), nil
}

func open(key []byte, data, aad string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil || len(raw) < 1+nonceLen+16 || raw[0] != formatVersion {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, raw[1:1+nonceLen], raw[1+nonceLen:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, errors.New("key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) // never fails (crypto/rand panics instead)
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
