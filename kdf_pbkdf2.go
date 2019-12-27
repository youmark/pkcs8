package pkcs8

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

var (
	oidPKCS5PBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidHMACWithMD5        = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidHMACWithSHA1       = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidHMACWithSHA512_224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 12}
	oidHMACWithSHA512_256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 13}
)

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

func init() {
	RegisterKDF(oidPKCS5PBKDF2, func() KDFParameters {
		return new(pbkdf2Params)
	})
}

func newHashFromPRF(ai pkix.AlgorithmIdentifier) (func() hash.Hash, error) {
	switch {
	case len(ai.Algorithm) == 0 || ai.Algorithm.Equal(oidHMACWithSHA1):
		return sha1.New, nil
	case ai.Algorithm.Equal(oidHMACWithMD5):
		return md5.New, nil
	case ai.Algorithm.Equal(oidHMACWithSHA224):
		return sha256.New224, nil
	case ai.Algorithm.Equal(oidHMACWithSHA256):
		return sha256.New, nil
	case ai.Algorithm.Equal(oidHMACWithSHA384):
		return sha512.New384, nil
	case ai.Algorithm.Equal(oidHMACWithSHA512):
		return sha512.New, nil
	case ai.Algorithm.Equal(oidHMACWithSHA512_224):
		return sha512.New512_224, nil
	case ai.Algorithm.Equal(oidHMACWithSHA512_256):
		return sha512.New512_256, nil
	default:
		return nil, errors.New("pkcs8: unsupported hash function")
	}
}

func newPRFParamFromHash(h crypto.Hash) (pkix.AlgorithmIdentifier, error) {

	var retIdentifier = pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{},
		Parameters: asn1.RawValue{Tag: asn1.TagNull},
	}

	switch h {
	case crypto.MD5:
		retIdentifier.Algorithm = oidHMACWithMD5
	case crypto.SHA1:
		retIdentifier.Algorithm = oidHMACWithSHA1
	case crypto.SHA224:
		retIdentifier.Algorithm = oidHMACWithSHA224
	case crypto.SHA256:
		retIdentifier.Algorithm = oidHMACWithSHA256
	case crypto.SHA384:
		retIdentifier.Algorithm = oidHMACWithSHA384
	case crypto.SHA512:
		retIdentifier.Algorithm = oidHMACWithSHA512
	case crypto.SHA512_224:
		retIdentifier.Algorithm = oidHMACWithSHA512_224
	case crypto.SHA512_256:
		retIdentifier.Algorithm = oidHMACWithSHA512_256
	default:
		return pkix.AlgorithmIdentifier{}, errors.New("pkcs8: unsupported hash function")
	}

	return retIdentifier, nil
}

func (p pbkdf2Params) DeriveKey(password []byte, size int) (key []byte, err error) {
	h, err := newHashFromPRF(p.PRF)
	if err != nil {
		return nil, err
	}
	if p.KeyLength != size && p.KeyLength != 0 {
		return nil, errors.New("pkcs8: key length missmatch")
	}
	return pbkdf2.Key(password, p.Salt, p.IterationCount, size, h), nil
}

// PBKDF2Opts contains options for the PBKDF2 key derivation function.
type PBKDF2Opts struct {
	SaltSize       int
	IterationCount int
	HMACHash       crypto.Hash
}

func (p PBKDF2Opts) DeriveKey(password, salt []byte, size int) (
	key []byte, params KDFParameters, err error) {

	key = pbkdf2.Key(password, salt, p.IterationCount, size, p.HMACHash.New)
	prfParam, err := newPRFParamFromHash(p.HMACHash)
	if err != nil {
		return nil, nil, err
	}
	params = pbkdf2Params{salt, p.IterationCount, size, prfParam}
	return key, params, nil
}

func (p PBKDF2Opts) GetSaltSize() int {
	return p.SaltSize
}

func (p PBKDF2Opts) OID() asn1.ObjectIdentifier {
	return oidPKCS5PBKDF2
}
