package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"log"
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

func encodePrivKeyToPEM(privateKey *rsa.PrivateKey) ([]byte, error) {

	var err error
	var privBlock *pem.Block

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	if flags.keyPassword != "" {
		privBlock, err = x509.EncryptPEMBlock(rand.Reader, RsaPrivKeyType, privDER, []byte(flags.keyPassword), x509.PEMCipherDES)
		if err != nil {
			return nil, err
		}
	} else {
		privBlock = &pem.Block{
			Type:    RsaPrivKeyType,
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

func generateSshKeyPair(bitSize int) ([]byte, []byte, error) {

	privateKey, err := generatePrivKey(bitSize)

	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)

	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := encodePrivKeyToPEM(privateKey)

	if err != nil {
		return nil, nil, err
	}

	return privateKeyBytes, publicKeyBytes, nil

}
