package util

import (
	"crypto/mldsa"
	"encoding/pem"
	"testing"

	"github.com/youmark/pkcs8"
)

func TestEncryptPkcs1PrivateKeyRejectsMLDSA(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	der, err := pkcs8.MarshalPrivateKey(priv, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncryptPkcs1PrivateKey(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "s3cret!"); err == nil {
		t.Fatal("legacy PEM encryption should be rejected for ML-DSA keys")
	}
}
