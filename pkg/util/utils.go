package util

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/youmark/pkcs8"
	"os"
	"time"
)

func ConvertSecondsToTime(t int64) time.Time {
	return time.Unix(0, t*int64(time.Second))
}

func GetJsonAsString(i interface{}) (s string) {
	byte, _ := json.MarshalIndent(i, "", "  ")
	s = string(byte)
	return
}

func SaveZipFile(path string, dataByte []byte) error {

	file, err := os.OpenFile(path+".zip", os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0666)

	if err != nil {
		return err
	}

	defer file.Close()

	_, err = file.Write(dataByte)

	if err != nil {
		return err
	}

	return nil
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
