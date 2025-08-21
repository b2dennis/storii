package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"

	"github.com/b2dennis/storii/internal/models"
	"golang.org/x/crypto/argon2"
)

func EncryptPassword(secret, masterPassword []byte) models.StoredPassword {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)

	iv := make([]byte, 12)
	_, _ = rand.Read(iv)

	key := argon2.IDKey(masterPassword, salt, 3, 64*1024, 2, 32)

	block, _ := aes.NewCipher(key)

	aesgcm, _ := cipher.NewGCM(block)

	ciphertext := aesgcm.Seal(nil, iv, secret, nil)

	tag := ciphertext[len(ciphertext)-16:]

	ct := ciphertext[:len(ciphertext)-16]

	ctHex := make([]byte, len(ct)*2)
	ivHex := make([]byte, len(iv)*2)
	tagHex := make([]byte, len(tag)*2)
	saltHex := make([]byte, len(salt)*2)

	hex.Encode(ctHex, ct)
	hex.Encode(ivHex, iv)
	hex.Encode(tagHex, tag)
	hex.Encode(saltHex, salt)

	return models.StoredPassword{
		Value:   ctHex,
		IV:      ivHex,
		AuthTag: tagHex,
		Salt:    saltHex,
	}
}

func DecryptPassword(ctHex, ivHex, tagHex, saltHex, masterPassword string) (string, error) {
	ct := make([]byte, len(ctHex)/2)
	iv := make([]byte, len(ivHex)/2)
	tag := make([]byte, len(tagHex)/2)
	salt := make([]byte, len(saltHex)/2)

	_, err := hex.Decode(ct, []byte(ctHex))
	if err != nil {
		return "", err
	}

	_, err = hex.Decode(iv, []byte(ivHex))
	if err != nil {
		return "", err
	}

	_, err = hex.Decode(tag, []byte(tagHex))
	if err != nil {
		return "", err
	}

	_, err = hex.Decode(salt, []byte(saltHex))
	if err != nil {
		return "", err
	}

	key := argon2.IDKey([]byte(masterPassword), salt, 3, 64*1024, 2, 32)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Reconstruct the full ciphertext (data + tag)
	ciphertext := append(ct, tag...)

	// Decrypt
	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
