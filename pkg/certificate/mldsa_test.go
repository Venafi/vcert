/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package certificate

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Venafi/vcert/v5/pkg/util"
)

func TestGenerateCertificateRequestWithMLDSAKey(t *testing.T) {
	expected := map[int]x509.SignatureAlgorithm{44: x509.MLDSA44, 65: x509.MLDSA65, 87: x509.MLDSA87}
	for _, strength := range AllSupportedMLDSAStrengths() {
		req := getCertificateRequestForTest()
		req.KeyType = KeyTypeMLDSA
		req.KeyStrength = strength

		err := req.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("Error generating ML-DSA-%d Private Key\nError: %s", strength, err)
		}
		err = req.GenerateCSR()
		if err != nil {
			t.Fatalf("Error generating Certificate Request\nError: %s", err)
		}

		pemBlock, _ := pem.Decode(req.GetCSR())
		if pemBlock == nil {
			t.Fatalf("Failed to decode CSR as PEM")
		}
		parsedReq, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			t.Fatalf("Error parsing generated Certificate Request\nError: %s", err)
		}
		if parsedReq.PublicKeyAlgorithm != x509.MLDSA {
			t.Fatalf("Expected public key algorithm %s, got %s", x509.MLDSA, parsedReq.PublicKeyAlgorithm)
		}
		if parsedReq.SignatureAlgorithm != expected[strength] {
			t.Fatalf("Expected signature algorithm %s, got %s", expected[strength], parsedReq.SignatureAlgorithm)
		}
		err = parsedReq.CheckSignature()
		if err != nil {
			t.Fatalf("Error checking signature of generated Certificate Request\nError: %s", err)
		}
	}
}

func TestGenerateMLDSAPrivateKeyInvalidStrength(t *testing.T) {
	for _, strength := range []int{0, 2048, 64} {
		req := getCertificateRequestForTest()
		req.KeyType = KeyTypeMLDSA
		req.KeyStrength = strength
		if err := req.GeneratePrivateKey(); err == nil {
			t.Fatalf("Expected an error for ML-DSA strength %d", strength)
		}
	}
}

func TestMLDSAPrivateKeyPEMBlock(t *testing.T) {
	priv, err := GenerateMLDSAPrivateKey(65)
	if err != nil {
		t.Fatalf("Error generating ML-DSA Private Key\nError: %s", err)
	}

	p, err := GetPrivateKeyPEMBock(priv)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		t.Fatalf("Error parsing PKCS8 ML-DSA key\nError: %s", err)
	}
	if !priv.(*mldsa.PrivateKey).Equal(parsed) {
		t.Fatalf("Parsed ML-DSA key does not match the generated one")
	}

	p, err = GetEncryptedPrivateKeyPEMBock(priv, []byte("something"))
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	str, err := util.DecryptPkcs8PrivateKey(string(pem.EncodeToMemory(p)), "something")
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	p, _ = pem.Decode([]byte(str))
	if p == nil {
		t.Fatalf("missing private key PEM")
	}
	parsed, err = x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		t.Fatalf("Error parsing decrypted PKCS8 ML-DSA key\nError: %s", err)
	}
	if !priv.(*mldsa.PrivateKey).Equal(parsed) {
		t.Fatalf("Decrypted ML-DSA key does not match the generated one")
	}

	if _, err = GetPrivateKeyPEMBock(priv, "legacy-pem"); err == nil {
		t.Fatalf("Expected an error for legacy-pem ML-DSA key")
	}
	if _, err = GetEncryptedPrivateKeyPEMBock(priv, []byte("something"), "legacy-pem"); err == nil {
		t.Fatalf("Expected an error for legacy-pem encrypted ML-DSA key")
	}
}

func TestMLDSACheckCertificateAndNewRequest(t *testing.T) {
	req := getCertificateRequestForTest()
	req.KeyType = KeyTypeMLDSA
	req.KeyStrength = 87
	if err := req.GeneratePrivateKey(); err != nil {
		t.Fatalf("Error generating ML-DSA Private Key\nError: %s", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      req.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, req.PrivateKey.Public(), req.PrivateKey)
	if err != nil {
		t.Fatalf("Error creating ML-DSA certificate\nError: %s", err)
	}
	certPEM := string(pem.EncodeToMemory(GetCertificatePEMBlock(der)))

	if err = req.CheckCertificate(certPEM); err != nil {
		t.Fatalf("CheckCertificate failed for matching ML-DSA key\nError: %s", err)
	}

	other := getCertificateRequestForTest()
	other.KeyType = KeyTypeMLDSA
	other.KeyStrength = 87
	if err = other.GeneratePrivateKey(); err != nil {
		t.Fatalf("Error generating ML-DSA Private Key\nError: %s", err)
	}
	if err = other.CheckCertificate(certPEM); err == nil {
		t.Fatalf("CheckCertificate was expected to fail for a different ML-DSA key")
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Error parsing ML-DSA certificate\nError: %s", err)
	}
	renew := NewRequest(cert)
	if renew.KeyType != KeyTypeMLDSA || renew.KeyStrength != 87 {
		t.Fatalf("NewRequest returned key type %s and strength %d, expected MLDSA and 87", renew.KeyType.String(), renew.KeyStrength)
	}
	// the strength must not be carried as an RSA key size
	if renew.KeyLength != 0 {
		t.Fatalf("NewRequest set KeyLength to %d for an ML-DSA key, expected 0", renew.KeyLength)
	}
}

func TestGenerateCSRReturnsCreateError(t *testing.T) {
	req := &Request{Subject: pkix.Name{CommonName: "no.key"}}
	if err := req.GenerateCSR(); err == nil || !strings.Contains(err.Error(), "failed to create certificate request") {
		t.Fatalf("expected the CSR creation error, got %v", err)
	}
}
