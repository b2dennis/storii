package passkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/big"
)

// CNG public key blob magics (bcrypt.h).
const (
	cngECDSAP256 = 0x31534345 // ECS1
	cngECDSAP384 = 0x33534345 // ECS3
	cngECDSAP521 = 0x35534345 // ECS5
	cngRSAPublic = 0x31415352 // RSA1
)

// VerifyCNG checks Windows' signature over a plugin request: sig signs SHA-256(data) with the operation signing key
// that WebAuthNPluginGetOperationSigningPublicKey returns as a BCRYPT_PUBLIC_KEY_BLOB. ECDSA signatures are raw r||s,
// RSA ones PSS with SHA-256 (as the PasskeyManager sample verifies them).
func VerifyCNG(blob, data, sig []byte) error {
	if len(blob) < 8 {
		return errors.New("key blob too short")
	}
	magic := binary.LittleEndian.Uint32(blob)
	digest := sha256.Sum256(data)
	switch magic {
	case cngECDSAP256, cngECDSAP384, cngECDSAP521:
		curve := map[uint32]elliptic.Curve{cngECDSAP256: elliptic.P256(), cngECDSAP384: elliptic.P384(), cngECDSAP521: elliptic.P521()}[magic]
		n := int(binary.LittleEndian.Uint32(blob[4:]))
		if n != (curve.Params().BitSize+7)/8 || len(blob) != 8+2*n {
			return errors.New("bad ECDSA key blob")
		}
		if len(sig) != 2*n {
			return errors.New("bad signature length")
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(blob[8 : 8+n]), Y: new(big.Int).SetBytes(blob[8+n:])}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return errors.New("key not on curve")
		}
		if !ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:n]), new(big.Int).SetBytes(sig[n:])) {
			return errors.New("bad signature")
		}
		return nil
	case cngRSAPublic:
		if len(blob) < 24 {
			return errors.New("bad RSA key blob")
		}
		ne := int(binary.LittleEndian.Uint32(blob[8:]))
		nm := int(binary.LittleEndian.Uint32(blob[12:]))
		if ne == 0 || ne > 8 || nm == 0 || len(blob) < 24+ne+nm {
			return errors.New("bad RSA key blob")
		}
		e := new(big.Int).SetBytes(blob[24 : 24+ne])
		if !e.IsInt64() || e.Int64() > 1<<31 {
			return errors.New("bad RSA exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(blob[24+ne : 24+ne+nm]), E: int(e.Int64())}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
			return errors.New("bad signature")
		}
		return nil
	}
	return errors.New("unknown key type")
}
