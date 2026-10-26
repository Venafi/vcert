package util

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	// nolint:gosec // only used to decrypt private keys TPP protects with its 3DES PBE option, never to encrypt
	"crypto/des"
	"crypto/pbkdf2"
	// nolint:gosec // HMAC-SHA1 is the PBKDF2 default PRF, only used to decrypt private keys, never to encrypt
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"github.com/youmark/pkcs8"
)

var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}

	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

type pkcs8PrivateKeyInfo struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	// optional attributes and public key omitted
}

// mldsaBothPrivateKey is the "both" form of an ML-DSA private key (seed and expanded key), which CyberArk Certificate
// Manager, Self-Hosted and OpenSSL write by default
type mldsaBothPrivateKey struct {
	Seed        []byte
	ExpandedKey []byte
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedData       []byte
}

type pbes2Params struct {
	KeyDerivationFunc pkix.AlgorithmIdentifier
	EncryptionScheme  pkix.AlgorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                      `asn1:"optional"`
	PRF            pkix.AlgorithmIdentifier `asn1:"optional"`
}

// ParsePKCS8PrivateKey parses a PKCS#8 private key, encrypted with PBES2 when password is not empty.
//
// Besides what pkcs8.ParsePrivateKey supports, it accepts ML-DSA private keys in the "both" form (seed and expanded
// key) returned by CyberArk Certificate Manager, Self-Hosted and written by OpenSSL, which Go only supports in the
// seed-only form. The seed defines the key, so the expanded key is ignored.
func ParsePKCS8PrivateKey(der []byte, password []byte) (crypto.PrivateKey, error) {
	key, _, err := pkcs8.ParsePrivateKey(der, password)
	if err == nil {
		return key, nil
	}

	plain := der
	if len(password) > 0 {
		decrypted, decryptErr := decryptPBES2(der, password)
		if decryptErr != nil {
			return nil, err
		}
		plain = decrypted
	}
	normalized, isMLDSA, normalizeErr := normalizeMLDSAPKCS8(plain)
	if normalizeErr != nil {
		return nil, normalizeErr
	}
	if !isMLDSA {
		return nil, err
	}
	return x509.ParsePKCS8PrivateKey(normalized)
}

// normalizeMLDSAPKCS8 rewrites a PKCS#8 ML-DSA private key in the "both" form to the seed-only form. isMLDSA is false
// when der is not an ML-DSA private key, in which case der is returned unchanged.
func normalizeMLDSAPKCS8(der []byte) (normalized []byte, isMLDSA bool, err error) {
	var info pkcs8PrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return der, false, nil
	}
	if !info.Algo.Algorithm.Equal(oidMLDSA44) && !info.Algo.Algorithm.Equal(oidMLDSA65) && !info.Algo.Algorithm.Equal(oidMLDSA87) {
		return der, false, nil
	}

	var privateKey asn1.RawValue
	if _, err := asn1.Unmarshal(info.PrivateKey, &privateKey); err != nil {
		return nil, true, fmt.Errorf("invalid ML-DSA private key: %w", err)
	}
	switch {
	case privateKey.Class == asn1.ClassContextSpecific && privateKey.Tag == 0:
		// already the seed-only form
		return der, true, nil
	case privateKey.Class == asn1.ClassUniversal && privateKey.Tag == asn1.TagSequence:
		var both mldsaBothPrivateKey
		if _, err := asn1.Unmarshal(info.PrivateKey, &both); err != nil {
			return nil, true, fmt.Errorf("invalid ML-DSA private key: %w", err)
		}
		if len(both.Seed) != 32 {
			return nil, true, fmt.Errorf("invalid ML-DSA private key: seed is %d bytes, expected 32", len(both.Seed))
		}
		seed, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: both.Seed})
		if err != nil {
			return nil, true, err
		}
		normalized, err := asn1.Marshal(pkcs8PrivateKeyInfo{Version: info.Version, Algo: info.Algo, PrivateKey: seed})
		return normalized, true, err
	case privateKey.Class == asn1.ClassUniversal && privateKey.Tag == asn1.TagOctetString:
		return nil, true, errors.New("ML-DSA private keys without a seed (expanded key only) are not supported")
	default:
		return nil, true, errors.New("invalid ML-DSA private key: unknown encoding")
	}
}

// decryptPBES2 decrypts a PKCS#8 EncryptedPrivateKeyInfo protected with PBES2 (PBKDF2 with AES-CBC or 3DES-CBC), the
// schemes CyberArk Certificate Manager, Self-Hosted uses
func decryptPBES2(der []byte, password []byte) ([]byte, error) {
	var encrypted encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &encrypted); err != nil {
		return nil, errors.New("pkcs8: only PKCS #5 v2.0 supported")
	}
	if !encrypted.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, errors.New("pkcs8: only PBES2 supported")
	}
	var params pbes2Params
	if _, err := asn1.Unmarshal(encrypted.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, errors.New("pkcs8: invalid PBES2 parameters")
	}
	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, errors.New("pkcs8: only PBKDF2 supported")
	}
	var kdf pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdf); err != nil {
		return nil, errors.New("pkcs8: invalid PBKDF2 parameters")
	}

	var prf func() hash.Hash
	switch {
	case len(kdf.PRF.Algorithm) == 0 || kdf.PRF.Algorithm.Equal(oidHMACWithSHA1):
		prf = sha1.New
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA224):
		prf = sha256.New224
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA256):
		prf = sha256.New
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA384):
		prf = sha512.New384
	case kdf.PRF.Algorithm.Equal(oidHMACWithSHA512):
		prf = sha512.New
	default:
		return nil, fmt.Errorf("pkcs8: unsupported PBKDF2 PRF %s", kdf.PRF.Algorithm)
	}

	var newBlock func(key []byte) (cipher.Block, error)
	var keySize int
	switch scheme := params.EncryptionScheme.Algorithm; {
	case scheme.Equal(oidAES128CBC):
		newBlock, keySize = aes.NewCipher, 16
	case scheme.Equal(oidAES192CBC):
		newBlock, keySize = aes.NewCipher, 24
	case scheme.Equal(oidAES256CBC):
		newBlock, keySize = aes.NewCipher, 32
	case scheme.Equal(oidDESEDE3CBC):
		newBlock, keySize = des.NewTripleDESCipher, 24
	default:
		return nil, fmt.Errorf("pkcs8: unsupported encryption scheme %s", scheme)
	}
	var iv []byte
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, errors.New("pkcs8: invalid encryption scheme parameters")
	}

	key, err := pbkdf2.Key(prf, string(password), kdf.Salt, kdf.IterationCount, keySize)
	if err != nil {
		return nil, err
	}
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	data := encrypted.EncryptedData
	if len(iv) != block.BlockSize() || len(data) == 0 || len(data)%block.BlockSize() != 0 {
		return nil, errors.New("pkcs8: invalid encrypted data")
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)

	padding := int(plain[len(plain)-1])
	if padding == 0 || padding > block.BlockSize() {
		return nil, errors.New("pkcs8: incorrect password")
	}
	for _, b := range plain[len(plain)-padding:] {
		if int(b) != padding {
			return nil, errors.New("pkcs8: incorrect password")
		}
	}
	return plain[:len(plain)-padding], nil
}
