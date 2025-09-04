package util

import (
	"testing"
)

func TestGenerateSshKeyPair(t *testing.T) {
	privKey, publicKey, err := GenerateSshKeyPair(3072, "1234", "cert-test")

	if err != nil {
		t.Fatalf("Error building ssh keys \nError: %s", err)
	}

	if len(privKey) == 0 {
		t.Fatalf("private key is empty")
	}
	if len(publicKey) == 0 {
		t.Fatalf("public key is empty")

	}

}

func TestGenerateSshKeyPairPassLess(t *testing.T) {
	privKey, publicKey, err := GenerateSshKeyPair(3072, "", "cert-test")

	if err != nil {
		t.Fatalf("Error building ssh keys \nError: %s", err)
	}

	if len(privKey) == 0 {
		t.Fatalf("private key is empty")
	}
	if len(publicKey) == 0 {
		t.Fatalf("public key is empty")

	}

}

func TestGenerateSshKeyPairLegacyPem(t *testing.T) {
	privKey, publicKey, err := GenerateSshKeyPair(3072, "1234", "cert-test", "legacy-pem")

	if err != nil {
		t.Fatalf("Error building ssh keys \nError: %s", err)
	}

	if len(privKey) == 0 {
		t.Fatalf("private key is empty")
	}
	if len(publicKey) == 0 {
		t.Fatalf("public key is empty")

	}

}

func TestGenerateSshKeyPairLegacyPemPassLess(t *testing.T) {
	privKey, publicKey, err := GenerateSshKeyPair(3072, "", "cert-test", "legacy-pem")

	if err != nil {
		t.Fatalf("Error building ssh keys \nError: %s", err)
	}

	if len(privKey) == 0 {
		t.Fatalf("private key is empty")
	}
	if len(publicKey) == 0 {
		t.Fatalf("public key is empty")

	}

}
