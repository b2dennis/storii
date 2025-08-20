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
