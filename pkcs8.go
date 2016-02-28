// Package pkcs8 implements functions to parse and convert private keys in PKCS#8 format, as defined in RFC5208 and RFC5958
package pkcs8

import (
	"golang.org/x/crypto/pbkdf2"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
)

// Copy from crypto/x509
var (
	oidPublicKeyRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyDSA   = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// Copy from crypto/x509
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

// Copy from crypto/x509
func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

// Unecrypted PKCS8
var (
	oidPKCS5PBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBES2       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidAES256CBC   = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type privateKeyInfo struct {
	Version             int
	PrivateKeyAlgorithm []asn1.ObjectIdentifier
	PrivateKey          []byte
}

// Encrypted PKCS8
type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
}

type pbkdf2Algorithms struct {
	IdPBKDF2     asn1.ObjectIdentifier
	PBKDF2Params pbkdf2Params
}

type pbkdf2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

type pbes2Params struct {
	KeyDerivationFunc pbkdf2Algorithms
	EncryptionScheme  pbkdf2Encs
}

type pbes2Algorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	PBES2Params pbes2Params
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pbes2Algorithms
	EncryptedData       []byte
}

// ParsePKCS8PrivateKey parses encrypted/unencrypted private keys in PKCS#8 format. To parse encrypted private keys, a password of []byte type should be provided to the function as the second parameter.
//
// The function can decrypt the private key encrypted with AES-256-CBC mode, and stored in PKCS #5 v2.0 format.
func ParsePKCS8PrivateKey(der []byte, v ...[]byte) (key interface{}, err error) {
	// No password provided, assume the private key is unencrypted
	if v == nil {
		key, err = x509.ParsePKCS8PrivateKey(der)
		return
        }

	// Use the password provided to decrypt the private key
	password := v[0]
	var privKey encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &privKey); err != nil {
		return nil, errors.New("pkcs8: only PKCS #5 v2.0 supported")
	}

	if !privKey.EncryptionAlgorithm.IdPBES2.Equal(oidPBES2) {
		return nil, errors.New("pkcs8: only PBES2 supported")
	}

	if !privKey.EncryptionAlgorithm.PBES2Params.KeyDerivationFunc.IdPBKDF2.Equal(oidPKCS5PBKDF2) {
		return nil, errors.New("pkcs8: only PBKDF2 supported")
	}

	encParam := privKey.EncryptionAlgorithm.PBES2Params.EncryptionScheme
	kdfParam := privKey.EncryptionAlgorithm.PBES2Params.KeyDerivationFunc.PBKDF2Params

	switch {
	case encParam.EncryAlgo.Equal(oidAES256CBC):
		iv := encParam.IV
		salt := kdfParam.Salt
		iter := kdfParam.IterationCount

		encryptedKey := privKey.EncryptedData
		symkey := pbkdf2.Key(password, salt, iter, 32, sha1.New)
		block, err := aes.NewCipher(symkey)
		if err != nil {
			return nil, err
		}
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(encryptedKey, encryptedKey)

		key, err = x509.ParsePKCS8PrivateKey(encryptedKey)
		if err != nil {
			return nil, errors.New("pkcs8: incorrect password")
		}

		return x509.ParsePKCS8PrivateKey(encryptedKey)
	default:
		return nil, errors.New("pkcs8: only AES-256-CBC supported")

	}
	return
}

func convertPrivateKeyToPKCS8(priv interface{}) (der []byte, err error) {
	var rb []byte
	var pkey privateKeyInfo

	switch priv := priv.(type) {
	case *ecdsa.PrivateKey:
		eckey, err := x509.MarshalECPrivateKey(priv)
		if err != nil {
			return nil, err
		}

		oidNamedCurve, ok := oidFromNamedCurve(priv.Curve)
		if !ok {
			return nil, errors.New("pkcs8: unknown elliptic curve")
		}

		// Per RFC5958, if publicKey is present, then version is set to v2(1) else version is set to v1(0).
		// But openssl set to v1 even publicKey is present
		pkey.Version = 1
		pkey.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 2)
		pkey.PrivateKeyAlgorithm[0] = oidPublicKeyECDSA
		pkey.PrivateKeyAlgorithm[1] = oidNamedCurve
		pkey.PrivateKey = eckey
	case *rsa.PrivateKey:

		// Per RFC5958, if publicKey is present, then version is set to v2(1) else version is set to v1(0).
		// But openssl set to v1 even publicKey is present
		pkey.Version = 0
		pkey.PrivateKeyAlgorithm = make([]asn1.ObjectIdentifier, 1)
		pkey.PrivateKeyAlgorithm[0] = oidPublicKeyRSA
		pkey.PrivateKey = x509.MarshalPKCS1PrivateKey(priv)
	}

	rb, err = asn1.Marshal(pkey)
	if err != nil {
		return nil, err
	}

	return rb, nil
}

func convertPrivateKeyToPKCS8Encrypted(priv interface{}, password []byte) (der []byte, err error) {
	// Convert private key into PKCS8 format
	pkey, err := convertPrivateKeyToPKCS8(priv)
	if err != nil {
		return nil, err
	}

	// Calculate key from password based on PKCS5 algorithm
	// Use 8 byte salt, 16 byte IV, and 2048 iteration
	iter := 2048
	var salt []byte = make([]byte, 8)
	var iv []byte = make([]byte, 16)
	rand.Reader.Read(salt)
	rand.Reader.Read(iv)
	key := pbkdf2.Key(password, salt, iter, 32, sha1.New)

	// Use AES256-CBC mode, pad plaintext with PKCS5 padding scheme
	padding := aes.BlockSize - len(pkey)%aes.BlockSize
	if padding > 0 {
		n := len(pkey)
		pkey = pkey[0 : n+padding]
		for i := 0; i < padding; i++ {
			pkey[n+i] = byte(padding)
		}
	}

	encryptedKey := make([]byte, len(pkey))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encryptedKey, pkey)

	pbkdf2algo := pbkdf2Algorithms{oidPKCS5PBKDF2, pbkdf2Params{salt, iter}}
	pbkdf2encs := pbkdf2Encs{oidAES256CBC, iv}
	pbes2algo := pbes2Algorithms{oidPBES2, pbes2Params{pbkdf2algo, pbkdf2encs}}

	encryptedPkey := encryptedPrivateKeyInfo{pbes2algo, encryptedKey}

	der, err = asn1.Marshal(encryptedPkey)
	if err != nil {
		return
	}

	return
}

// ConvertPrivateKeyToPKCS8 converts the private key into PKCS#8 format.
// To encrypt the private key, the password of []byte type should be provided as the second parameter.
//
// The only supported key types are RSA and ECDSA (*rsa.PublicKey or *ecdsa.PublicKey for priv)
func ConvertPrivateKeyToPKCS8(priv interface{}, v ...[]byte) (der []byte, err error) {
	if v == nil {
		der, err = convertPrivateKeyToPKCS8(priv)

		if err != nil {
			return nil, err
		}
	} else {
		password := string(v[0])
		der, err = convertPrivateKeyToPKCS8Encrypted(priv, []byte(password))
	}

	return der, err
}
