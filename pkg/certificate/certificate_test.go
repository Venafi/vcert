/*
 * Copyright 2018 Venafi, Inc.
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
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

func getCertificateRequestForTest() *Request {
	req := Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Engineering", "Automated Tests"}
	req.Subject.Country = []string{"US"}
	req.Subject.Locality = []string{"SLC"}
	req.Subject.Province = []string{"Utah"}

	host, _ := os.Hostname()
	req.DNSNames = []string{host}

	addrs, _ := net.InterfaceAddrs()
	var ips []net.IP
	for _, add := range addrs {
		ip, _, _ := net.ParseCIDR(add.String())
		v4 := ip.To4()
		if v4 != nil && !v4.IsLoopback() {
			ips = append(ips, ip)
		}

	}
	req.IPAddresses = ips
	return &req
}

func generateTestCertificate() (*x509.Certificate, interface{}, error) {
	req := getCertificateRequestForTest()

	priv, err := GenerateECDSAPrivateKey(EllipticCurveP384)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := generateSelfSigned(req, x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func generateSelfSigned(request *Request, ku x509.KeyUsage, eku []x509.ExtKeyUsage, privateKey interface{}) ([]byte, error) {
	notBefore := time.Now()
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, _ := rand.Int(rand.Reader, limit)

	certRequest := x509.Certificate{
		SerialNumber: serial,
	}
	certRequest.Subject = request.Subject
	certRequest.DNSNames = request.DNSNames
	certRequest.EmailAddresses = request.EmailAddresses
	certRequest.IPAddresses = request.IPAddresses
	certRequest.SignatureAlgorithm = request.SignatureAlgorithm
	certRequest.PublicKeyAlgorithm = request.PublicKeyAlgorithm
	certRequest.ExtKeyUsage = eku
	certRequest.NotBefore = notBefore.UTC()
	if ku&x509.KeyUsageCertSign != x509.KeyUsageCertSign {
		certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 90)
		certRequest.IsCA = false
	} else {
		certRequest.NotAfter = certRequest.NotBefore.AddDate(0, 0, 180)
		certRequest.IsCA = true
	}
	certRequest.BasicConstraintsValid = true

	pub := publicKey(privateKey)

	cert, err := x509.CreateCertificate(rand.Reader, &certRequest, &certRequest, pub, privateKey)
	if err != nil {
		cert = nil
	}

	return cert, err
}

func TestGenerateRSAPrivateKey(t *testing.T) {
	priv, err := GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}

	err = priv.Validate()
	if err != nil {
		t.Fatalf("Error validating RSA Private Key\nError: %s", err)
	}
}

func TestGenerateECDSAPrivateKey(t *testing.T) {
	ellipticCurves := []EllipticCurve{EllipticCurveP224, EllipticCurveP256, EllipticCurveP384, EllipticCurveP521}
	for _, curve := range ellipticCurves {
		_, err := GenerateECDSAPrivateKey(curve)
		if err != nil {
			t.Fatalf("Error generating ECDSA Private Key\nError: %s", err)
		}
	}
}

func TestGenerateCertificateRequestWithRSAKey(t *testing.T) {
	req := getCertificateRequestForTest()

	priv, err := GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}

	err = GenerateRequest(req, priv)
	if err != nil {
		t.Fatalf("Error generating Certificate Request\nError: %s", err)
	}

	pem := GetCertificateRequestPEMBlock(req.CSR)
	if pem == nil {
		t.Fatalf("Failed to encode CSR as PEM")
	}

	parsedReq, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		t.Fatalf("Error parsing generated Certificate Request\nError: %s", err)
	}

	err = parsedReq.CheckSignature()
	if err != nil {
		t.Fatalf("Error checking signature of generated Certificate Request\nError: %s", err)
	}
}

func TestGenerateCertificateRequestWithECDSAKey(t *testing.T) {
	req := getCertificateRequestForTest()

	priv, err := GenerateECDSAPrivateKey(EllipticCurveP521)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}

	err = GenerateRequest(req, priv)
	if err != nil {
		t.Fatalf("Error generating Certificate Request\nError: %s", err)
	}

	pem := GetCertificateRequestPEMBlock(req.CSR)
	if pem == nil {
		t.Fatalf("Failed to encode CSR as PEM")
	}

	parsedReq, err := x509.ParseCertificateRequest(req.CSR)
	if err != nil {
		t.Fatalf("Error parsing generated Certificate Request\nError: %s", err)
	}

	err = parsedReq.CheckSignature()
	if err != nil {
		t.Fatalf("Error checking signature of generated Certificate Request\nError: %s", err)
	}
}

func TestEllipticCurveString(t *testing.T) {
	curve := EllipticCurveP521
	stringCurve := curve.String()
	if stringCurve != "P521" {
		t.Fatalf("Unexpected string value was returned.  Expected: P521 Actual: %s", stringCurve)
	}
	curve = EllipticCurveP384
	stringCurve = curve.String()
	if stringCurve != "P384" {
		t.Fatalf("Unexpected string value was returned.  Expected: P384 Actual: %s", stringCurve)
	}
	curve = EllipticCurveP256
	stringCurve = curve.String()
	if stringCurve != "P256" {
		t.Fatalf("Unexpected string value was returned.  Expected: P256 Actual: %s", stringCurve)
	}
	curve = EllipticCurveP224
	stringCurve = curve.String()
	if stringCurve != "P224" {
		t.Fatalf("Unexpected string value was returned.  Expected: P224 Actual: %s", stringCurve)
	}
}

func TestEllipticCurveSetByString(t *testing.T) {
	curve := EllipticCurveP224
	curve.Set("P521")
	if curve != EllipticCurveP521 {
		t.Fatalf("Unexpected string value was returned.  Expected: P521 Actual: %s", curve.String())
	}
	curve.Set("P384")
	if curve != EllipticCurveP384 {
		t.Fatalf("Unexpected string value was returned.  Expected: P384 Actual: %s", curve.String())
	}
	curve.Set("P256")
	if curve != EllipticCurveP256 {
		t.Fatalf("Unexpected string value was returned.  Expected: P256 Actual: %s", curve.String())
	}
	curve.Set("P224")
	if curve != EllipticCurveP224 {
		t.Fatalf("Unexpected string value was returned.  Expected: P224 Actual: %s", curve.String())
	}
	curve.Set("p521")
	if curve != EllipticCurveP521 {
		t.Fatalf("Unexpected string value was returned.  Expected: p521 Actual: %s", curve.String())
	}
	curve.Set("p384")
	if curve != EllipticCurveP384 {
		t.Fatalf("Unexpected string value was returned.  Expected: p384 Actual: %s", curve.String())
	}
	curve.Set("p256")
	if curve != EllipticCurveP256 {
		t.Fatalf("Unexpected string value was returned.  Expected: p256 Actual: %s", curve.String())
	}
	curve.Set("p224")
	if curve != EllipticCurveP224 {
		t.Fatalf("Unexpected string value was returned.  Expected: p224 Actual: %s", curve.String())
	}
}

func TestKeyTypeString(t *testing.T) {
	keyType := KeyTypeECDSA
	s := keyType.String()
	if s != "ECDSA" {
		t.Fatalf("Unexpected string value was returned.  Expected: ECDSA Actual: %s", s)
	}
	keyType = KeyTypeRSA
	s = keyType.String()
	if s != "RSA" {
		t.Fatalf("Unexpected string value was returned.  Expected: RSA Actual: %s", s)
	}
	keyType = 5
	s = keyType.String()
	if s != "" {
		t.Fatalf("Unexpected string value was returned.  Expected: \"\" Actual: %s", s)
	}
}

func TestKeyTypeSetByString(t *testing.T) {
	keyType := KeyTypeRSA
	keyType.Set("rsa")
	if keyType != KeyTypeRSA {
		t.Fatalf("Unexpected string value was returned.  Expected: RSA Actual: %s", keyType.String())
	}
	keyType.Set("RSA")
	if keyType != KeyTypeRSA {
		t.Fatalf("Unexpected string value was returned.  Expected: RSA Actual: %s", keyType.String())
	}
	keyType.Set("ecdsa")
	if keyType != KeyTypeECDSA {
		t.Fatalf("Unexpected string value was returned.  Expected: ECDSA Actual: %s", keyType.String())
	}
	keyType.Set("ECDSA")
	if keyType != KeyTypeECDSA {
		t.Fatalf("Unexpected string value was returned.  Expected: ECDSA Actual: %s", keyType.String())
	}
}

func TestGetPrivateKeyPEMBock(t *testing.T) {
	var priv interface{}
	priv, err := GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}

	p, err := GetPrivateKeyPEMBock(priv)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	if p == nil {
		t.Fatalf("GetPrivateKeyPEMBock returned nil for RSA key")
	}

	ellipticCurves := []EllipticCurve{EllipticCurveP224, EllipticCurveP256, EllipticCurveP384, EllipticCurveP521}
	for _, curve := range ellipticCurves {
		priv, err = GenerateECDSAPrivateKey(curve)
		if err != nil {
			t.Fatalf("Error generating ECDSA Private Key\nError: %s", err)
		}

		p, err = GetPrivateKeyPEMBock(priv)
		if err != nil {
			t.Fatalf("Error: %s", err)
		}
		if p == nil {
			t.Fatalf("GetPrivateKeyPEMBock returned nil for ECDSA key")
		}
	}
}

func TestGetEncryptedPrivateKeyPEMBock(t *testing.T) {
	var priv interface{}
	priv, err := GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}

	p, err := GetEncryptedPrivateKeyPEMBock(priv, []byte("something"))
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	if p == nil {
		t.Fatalf("GetPrivateKeyPEMBock returned nil for RSA key")
	}

	b, err := x509.DecryptPEMBlock(p, []byte("something"))
	if err != nil {
		t.Fatalf("Error: %s", err)
	}
	_, err = x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	ellipticCurves := []EllipticCurve{EllipticCurveP224, EllipticCurveP256, EllipticCurveP384, EllipticCurveP521}
	for _, curve := range ellipticCurves {
		priv, err = GenerateECDSAPrivateKey(curve)
		if err != nil {
			t.Fatalf("Error generating ECDSA Private Key\nError: %s", err)
		}

		p, err = GetEncryptedPrivateKeyPEMBock(priv, []byte("something"))
		if err != nil {
			t.Fatalf("Error: %s", err)
		}
		if p == nil {
			t.Fatalf("GetPrivateKeyPEMBock returned nil for ECDSA key")
		}

		b, err := x509.DecryptPEMBlock(p, []byte("something"))
		if err != nil {
			t.Fatalf("Error: %s", err)
		}
		_, err = x509.ParseECPrivateKey(b)
		if err != nil {
			t.Fatalf("Error: %s", err)
		}
	}
}

func TestGetCertificatePEMBlock(t *testing.T) {
	cert, _, err := generateTestCertificate()
	if err != nil {
		t.Fatalf("Error generating test certificate\nError: %s", err)
	}
	certPem := GetCertificatePEMBlock(cert.Raw)
	if certPem == nil {
		t.Fatalf("GetCertificatePEMBlock returned nil pem block")
	}
}

func TestGetCertificateRequestPEMBlock(t *testing.T) {
	certRequest := getCertificateRequestForTest()
	var priv interface{}
	priv, err := GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}
	err = GenerateRequest(certRequest, priv)
	if err != nil {
		t.Fatalf("Error generating request\nError: %s", err)
	}
	csrPem := GetCertificateRequestPEMBlock(certRequest.CSR)
	if csrPem == nil {
		t.Fatalf("GetCertificateRequestPEMBlock returned nil pem block")
	}
}

func TestPublicKey(t *testing.T) {
	priv, _ := GenerateRSAPrivateKey(512)
	pub := PublicKey(priv)
	if pub == nil {
		t.Fatal("should return public key")
	}
}
