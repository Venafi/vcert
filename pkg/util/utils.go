package util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/youmark/pkcs8"
	"time"
)

const LegacyPem = "legacy-pem"

func ConvertSecondsToTime(t int64) time.Time {
	return time.Unix(0, t*int64(time.Second))
}

func GetJsonAsString(i interface{}) (s string) {
	byte, _ := json.MarshalIndent(i, "", "  ")
	s = string(byte)
	return
}

func DecryptPkcs8PrivateKey(privateKey, password string) (string, error) {

	block, _ := pem.Decode([]byte(privateKey))
	key, _, err := pkcs8.ParsePrivateKey(block.Bytes, []byte(password))

	if err != nil {
		return "", err
	}

	var pemType string

	switch key.(type) {
	case *rsa.PrivateKey:
		pemType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		pemType = "EC PRIVATE KEY"
	case ed25519.PrivateKey:
		pemType = "PRIVATE KEY"
	default:
		return "", fmt.Errorf("failed to determine private key type")
	}
	privateKeyBytes, err := pkcs8.MarshalPrivateKey(key, nil, nil)

	if err != nil {
		return "", err
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: privateKeyBytes})

	return string(pemBytes), nil
}

func EncryptPkcs1PrivateKey(privateKey, password string) (string, error) {

	block, _ := pem.Decode([]byte(privateKey))

	encrypted, err := X509EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", block.Bytes, []byte(password), PEMCipherAES256)

	if err != nil {
		return "", nil
	}
	return string(pem.EncodeToMemory(encrypted)), nil
}
