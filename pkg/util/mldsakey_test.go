package util

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/youmark/pkcs8"
)

// The fixtures are ML-DSA-44 keys written by OpenSSL 3.6 in its default "both" form (seed and expanded key), the
// form CyberArk Certificate Manager, Self-Hosted returns, encrypted with PBES2 like TPP does.
const mldsaFixturePassword = "vcert-test-pass"

func readPEMFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("%s is not PEM", name)
	}
	return block.Bytes
}

func fixturePublicKey(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	pub, err := x509.ParsePKIXPublicKey(readPEMFixture(t, "mldsa44-pub.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return pub.(*mldsa.PublicKey)
}

func TestParsePKCS8PrivateKeyMLDSABothForm(t *testing.T) {
	want := fixturePublicKey(t)
	cases := map[string][]byte{
		"mldsa44-both.pem":               nil,
		"mldsa44-both-aes256-sha256.pem": []byte(mldsaFixturePassword),
		"mldsa44-both-aes128-sha1.pem":   []byte(mldsaFixturePassword),
		"mldsa44-both-des3.pem":          []byte(mldsaFixturePassword),
	}
	for name, password := range cases {
		t.Run(name, func(t *testing.T) {
			der := readPEMFixture(t, name)
			if password == nil {
				if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
					t.Fatal("the fixture should be in the form Go doesn't parse")
				}
			}
			key, err := ParsePKCS8PrivateKey(der, password)
			if err != nil {
				t.Fatalf("ParsePKCS8PrivateKey: %s", err)
			}
			priv, ok := key.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("unexpected key type %T", key)
			}
			if !priv.PublicKey().Equal(want) {
				t.Fatal("the parsed key doesn't match the fixture's public key")
			}
		})
	}
}

func TestParsePKCS8PrivateKeyMLDSAErrors(t *testing.T) {
	if _, err := ParsePKCS8PrivateKey(readPEMFixture(t, "mldsa44-both-aes256-sha256.pem"), []byte("wrong password")); err == nil {
		t.Fatal("a wrong password should fail")
	}
	_, err := ParsePKCS8PrivateKey(readPEMFixture(t, "mldsa44-expanded.pem"), nil)
	if err == nil || !strings.Contains(err.Error(), "without a seed") {
		t.Fatalf("expected the expanded-only key to be rejected with a clear error, got %v", err)
	}
}

func TestParsePKCS8PrivateKeyOtherKeys(t *testing.T) {
	// keys that pkcs8.ParsePrivateKey already handles are unaffected
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mlKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []interface{}{ed, mlKey} {
		der, err := pkcs8.MarshalPrivateKey(key, []byte(mldsaFixturePassword), nil)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParsePKCS8PrivateKey(der, []byte(mldsaFixturePassword))
		if err != nil {
			t.Fatalf("%T: %s", key, err)
		}
		if !parsed.(interface {
			Equal(x crypto.PrivateKey) bool
		}).Equal(key) {
			t.Fatalf("%T: key changed", key)
		}
	}
}

func TestDecryptPkcs8PrivateKeyMLDSABothForm(t *testing.T) {
	data, err := os.ReadFile("testdata/mldsa44-both-aes256-sha256.pem")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptPkcs8PrivateKey(string(data), mldsaFixturePassword)
	if err != nil {
		t.Fatalf("DecryptPkcs8PrivateKey: %s", err)
	}
	block, _ := pem.Decode([]byte(decrypted))
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("unexpected output %q", decrypted)
	}
	// the output is the seed-only form, which Go parses
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("decrypted key is not readable by Go: %s", err)
	}
	if !key.(*mldsa.PrivateKey).PublicKey().Equal(fixturePublicKey(t)) {
		t.Fatal("decrypted key doesn't match the fixture")
	}
}

// VSatellite returns service generated keys, including ML-DSA keys, as PKCS#8 encrypted with
// pkcs8.MarshalPrivateKey and pkcs8.DefaultOpts (PBES2, PBKDF2 with HMAC-SHA256, AES-256-CBC)
func TestDecryptPkcs8PrivateKeyMLDSAFromVSatellite(t *testing.T) {
	for _, params := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(params.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(params)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := pkcs8.MarshalPrivateKey(key, []byte("vsat-pass"), pkcs8.DefaultOpts)
			if err != nil {
				t.Fatal(err)
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: encrypted})

			decrypted, err := DecryptPkcs8PrivateKey(string(keyPEM), "vsat-pass")
			if err != nil {
				t.Fatalf("DecryptPkcs8PrivateKey: %s", err)
			}
			block, _ := pem.Decode([]byte(decrypted))
			if block == nil || block.Type != "PRIVATE KEY" {
				t.Fatalf("unexpected output %q", decrypted)
			}
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				t.Fatalf("decrypted key is not readable by Go: %s", err)
			}
			if !parsed.(*mldsa.PrivateKey).PublicKey().Equal(key.PublicKey()) {
				t.Fatal("decrypted key doesn't match the generated key")
			}

			if _, err := DecryptPkcs8PrivateKey(string(keyPEM), "wrong-pass"); err == nil {
				t.Fatal("expected an error with the wrong password")
			}
		})
	}
}

func TestDecryptPkcs8PrivateKeyNotPEM(t *testing.T) {
	for _, input := range []string{"", "not a PEM block"} {
		if _, err := DecryptPkcs8PrivateKey(input, "pass"); err == nil {
			t.Fatalf("expected an error for %q", input)
		}
	}
}
