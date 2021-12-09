package util

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"github.com/youmark/pkcs8"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	RsaPrivKeyType = "RSA PRIVATE KEY"
)

func generatePrivKey(bitSize int) (*rsa.PrivateKey, error) {

	privKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privKey.Validate()
	if err != nil {
		return nil, err
	}

	log.Println("Private Key was generated")
	return privKey, nil
}

func encodePrivKeyToPEM(privateKey *rsa.PrivateKey, keyPassword string) ([]byte, error) {

	var err error
	var privBlock *pem.Block
	var privDER []byte
	if keyPassword != "" {
		privDER, err = pkcs8.MarshalPrivateKey(privateKey, []byte(keyPassword), nil)
		if err != nil {
			return nil, err
		}
		privBlock = &pem.Block{
			Type:    "ENCRYPTED PRIVATE KEY",
			Headers: nil,
			Bytes:   privDER,
		}
	} else {
		privDER, err := pkcs8.MarshalPrivateKey(privateKey, nil, nil)
		if err != nil {
			return nil, err
		}
		privBlock = &pem.Block{
			Type:    "PRIVATE KEY",
			Headers: nil,
			Bytes:   privDER,
		}
	}

	privatePEM := pem.EncodeToMemory(privBlock)

	return privatePEM, nil
}

func generatePublicKey(key *rsa.PublicKey) ([]byte, error) {

	publicRsaKey, err := ssh.NewPublicKey(key)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	log.Println("Public key was generated")
	return pubKeyBytes, nil

}

func GenerateSshKeyPair(bitSize int, keyPassword, certId string) ([]byte, []byte, error) {

	privateKey, err := generatePrivKey(bitSize)

	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)

	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := encodePrivKeyToPEM(privateKey, keyPassword)

	if err != nil {
		return nil, nil, err
	}

	sPubKey := string(publicKeyBytes)
	sPubKey = strings.TrimRight(sPubKey, "\r\n")
	sPubKey = fmt.Sprint(sPubKey, " ", certId)

	return privateKeyBytes, []byte(sPubKey), nil

}
