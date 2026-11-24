package util

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

const testCompanyID = "5c8f6a1e-2b3d-11ee-8000-000000000001"

func TestEncryptForEdgeKeyHPKERoundTrip(t *testing.T) {
	priv, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	plaintext := []byte("T1795127555-abcd.temp.pwd")

	out, err := EncryptForEdgeKey(plaintext, keyB64, EdgeKeyAlgorithmVSatHPKE, testCompanyID)
	if err != nil {
		t.Fatalf("EncryptForEdgeKey: %v", err)
	}
	got := openHPKE(t, priv, out, testCompanyID)
	if string(got) != string(plaintext) {
		t.Fatalf("decrypted %q, want %q", got, plaintext)
	}

	// The company ID is bound as info and additional data, so another company's VSatellite can't open it.
	if _, err := tryOpenHPKE(priv, out, "another-company"); err == nil {
		t.Fatal("decryption with a different company ID succeeded")
	}
}

func TestEncryptForEdgeKeyNaClRoundTrip(t *testing.T) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyB64 := base64.StdEncoding.EncodeToString(pub[:])
	plaintext := []byte("T1795127555-abcd.temp.pwd")

	// Older responses have no keyAlgorithm; those keys are ED25519.
	for _, alg := range []string{EdgeKeyAlgorithmED25519, ""} {
		out, err := EncryptForEdgeKey(plaintext, keyB64, alg, "")
		if err != nil {
			t.Fatalf("EncryptForEdgeKey(%q): %v", alg, err)
		}
		sealed, err := base64.StdEncoding.DecodeString(out)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := box.OpenAnonymous(nil, sealed, pub, priv)
		if !ok || string(got) != string(plaintext) {
			t.Fatalf("algorithm %q: sealed box did not open to the plaintext", alg)
		}
	}
}

func TestEncryptForEdgeKeyErrors(t *testing.T) {
	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Key := base64.StdEncoding.EncodeToString(p384.PublicKey().Bytes())
	key32 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	notOnCurve := make([]byte, 97)
	notOnCurve[0] = 0x04

	tests := []struct {
		name, key, alg, companyID, wantErr string
	}{
		{"unknown algorithm", key32, "RSA", testCompanyID, `unsupported VSatellite encryption key algorithm "RSA"`},
		{"P-384 key sent as ED25519", p384Key, EdgeKeyAlgorithmED25519, "", "has 97 bytes, ED25519 needs 32"},
		{"32-byte key sent as VSAT_HPKE", key32, EdgeKeyAlgorithmVSatHPKE, testCompanyID, "has 32 bytes, VSAT_HPKE needs 97"},
		{"VSAT_HPKE without company ID", p384Key, EdgeKeyAlgorithmVSatHPKE, "", "has no company ID"},
		{"point not on the curve", base64.StdEncoding.EncodeToString(notOnCurve), EdgeKeyAlgorithmVSatHPKE, testCompanyID, "invalid VSAT_HPKE"},
		{"bad base64", "not base64!", EdgeKeyAlgorithmED25519, "", "failed to decode"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := EncryptForEdgeKey([]byte("pwd"), tc.key, tc.alg, tc.companyID)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func openHPKE(t *testing.T, priv *ecdh.PrivateKey, out, companyID string) []byte {
	t.Helper()
	got, err := tryOpenHPKE(priv, out, companyID)
	if err != nil {
		t.Fatalf("HPKE open: %v", err)
	}
	return got
}

// tryOpenHPKE decrypts the way a VSAT_HPKE VSatellite does: enc is the first 97 bytes (a P-384 point).
func tryOpenHPKE(priv *ecdh.PrivateKey, out, companyID string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(out)
	if err != nil {
		return nil, err
	}
	encLen := len(priv.PublicKey().Bytes())
	privateKey, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	info := []byte(companyID)
	recipient, err := hpke.NewRecipient(raw[:encLen], privateKey, hpke.HKDFSHA512(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, err
	}
	return recipient.Open(info, raw[encLen:])
}
