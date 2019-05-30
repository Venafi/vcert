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
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"strings"
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

func generateTestCertificate() (*x509.Certificate, crypto.Signer, error) {
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

func generateSelfSigned(request *Request, ku x509.KeyUsage, eku []x509.ExtKeyUsage, privateKey crypto.Signer) ([]byte, error) {
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
	var err error
	req.PrivateKey, err = GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
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

	err = parsedReq.CheckSignature()
	if err != nil {
		t.Fatalf("Error checking signature of generated Certificate Request\nError: %s", err)
	}
}

func TestGenerateCertificateRequestWithECDSAKey(t *testing.T) {
	req := getCertificateRequestForTest()
	var err error
	req.PrivateKey, err = GenerateECDSAPrivateKey(EllipticCurveP521)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
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
	var priv crypto.Signer
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
	var priv crypto.Signer
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
	var priv crypto.Signer
	priv, err := GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}
	err = GenerateRequest(certRequest, priv)
	if err != nil {
		t.Fatalf("Error generating request\nError: %s", err)
	}
	csrPem := GetCertificateRequestPEMBlock(certRequest.GetCSR())
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

const (
	checkCertificatePrivateKeyRSAvalid = `
-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKiD4hrY58XqeYEB
yIg14R6R2Ia/53cBSkNhzRn7Q9wDIzA8qJUkGNu8Oz0nE2V3LhDXsNM7B+IgO1LB
YRBgegCKHpQVsYlnNUmETbJSILEsbEZZLCaMBXC/xONKpJi9E3qyNr6vNvYxd12O
l9RN3tTl6NJG5gS8BAf8Z6X7r6bdAgMBAAECgYEAjpLGgiByOCkhk9yGZXfwd4S9
xYQnubAFvOzKMuk7iLG+29j2aPiZb4/aLusYpggnmWhj2tNe4BqVFnc2QDzf+qTO
fEmDm1mBnc0V+k0Rt99Wq9KPVMAm2EJBFrUGK7VGQ3H4B02kS+ywz6z25mebCzBT
JlA7m3jaUdGJQEEPXgECQQDcVwlQrTPOxkG6UX3wfqtSgby0nVPH1N7h+aIVRbZY
wfdXFsJEIv9ePly0S8MFLpxBNczR4Dqpm6ViEGkUEM+tAkEAw8mt5TAw9//38x0n
ZyeYhGrM0qOMHHLw5XhnaJPiJ4NyU96aspr+Ppv4Z550f+Z3dIGSKnDinQly1jL1
f21Z8QJBAKrR7y7UmG2d1icUNobULQ3x9tIvhlxN891NIxNK0GtPNOoXgtRALapq
voQomDDUSd9kTj4HkHMdb8Hu5wffYKECQA5NBfGusnT68m6Em6MyRjat4mYkYhCV
6LiqMct2udcvB8POh7gyEA4csGlJLrNE70bITBfjhPn5fbTdpgb3wtECQQC4dQBg
335myMx7IDWT/I6R7i0Rx+WY7XZ84PkTwTd0q78yIhRS/42rgwEBMkkxlSg5X2sb
Xjw3nEoRoeTEToar
-----END PRIVATE KEY-----
`
	checkCertificatePrivateKeyRSAinvalid = `
-----BEGIN PRIVATE KEY-----
MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAKOZvVaHHImhKD+r
RZXJYV8busd0g0uWBGMeK+VltyG8H/h/neyPmHoEh62P/3FG3UP7oOAAGfz3/yCW
hf7fHmNz1d6/HyCdQvD4kz/e9E6ty+k1iM5X6pGS97xPsObgHfyOgLn1/YdKvq81
yG+O/mtfqQEI2izYUAbhUtq3qbctAgMBAAECgYAumTzH56YmQYQAVp10Y67bcz+J
TlOTdQB85vwj1AwMjNQiaN8noWMR5jZrJmfg8QlXMtYI156PYmgF9Tnndc/mmVlg
ow9mqEWjXZoBLCP++EkAbQ8dwmuGJB9WzIWFvj6bnKUOJAqQpsXv/wOqcrO7RZb0
h2Wt/08tpuMZSYnUtQJBANIOKhCxJGjRbPgiczPFauuPi/kqSl1tLFbJfK0XBOvg
Dezwz4YZpkhj1ttM6JB8QcDHEOMZ3XJMu+m8TqAB4cMCQQDHYmL7FzFg8QGeeeUe
a4EVFSxmN45y2qSq2KyN0eaeuuV+fHjiLFyi+rZ+gA9xnyQFWcwTH+tFvcbi5aI7
WgRPAkAC2XBWo6CDz3tz7juz0xS9N0hFy/4QQF/emYMYcfx+Gp71vNqDzitERh5v
AR8Sfq0BqXGgMwSe/U17QTOr1fqzAkAFiwixbl2jElA3NbBW/ioiieooFVdSfh2h
2lBByRoeQ5fpwlAiCZWxukKkla7YO9Jmi66OwY5q6/HBkRzHhaMlAkAEeP1wnnnQ
F3iRLaRPmLtKf8sO1onEkSaQAq5p8/RFvNNwwqMh1t9wu9UYIefICoFsK0wAza9j
4qQY8qM+To1X
-----END PRIVATE KEY-----
`
	checkCertificateCSRRSA = `
-----BEGIN CERTIFICATE REQUEST-----
MIIBrDCCARUCAQAwbDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxEjAQBgNV
BAcMCVNhbHQgTGFrZTEPMA0GA1UECgwGVmVuYWZpMQ8wDQYDVQQLDAZEZXZPcHMx
GDAWBgNVBAMMD3Rlc3QudmVuZGV2LmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEAqIPiGtjnxep5gQHIiDXhHpHYhr/ndwFKQ2HNGftD3AMjMDyolSQY27w7
PScTZXcuENew0zsH4iA7UsFhEGB6AIoelBWxiWc1SYRNslIgsSxsRlksJowFcL/E
40qkmL0TerI2vq829jF3XY6X1E3e1OXo0kbmBLwEB/xnpfuvpt0CAwEAAaAAMA0G
CSqGSIb3DQEBCwUAA4GBAGsKm5fJ8Zm/j9XMPXhPYmOdiDj+9QlcFq7uRRqwpxo7
C507RR5Pj2zBRZRLJcc/bNTQFqnW92kIcvJ+YvrQl/GkEMKM2wds/RyMXRHtOJvZ
YQt6JtkAeQOMECJ7RRHrZiG+m2by2YAB2krthK2gJGSr80xWzZWzrgdwdTe2sxUG
-----END CERTIFICATE REQUEST-----
`
	chechCertificateRSACert = `
-----BEGIN CERTIFICATE-----
MIICyjCCAbICCQDtS0qAZisbTTANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJV
UzENMAsGA1UECAwEVXRhaDESMBAGA1UEBwwJU2FsdCBMYWtlMQ8wDQYDVQQKDAZW
ZW5hZmkxDzANBgNVBAsMBkRldk9wczESMBAGA1UEAwwJVmVuYWZpIENBMB4XDTE5
MDMxNDE1MjAzMloXDTE5MDQxMzE1MjAzMlowbDELMAkGA1UEBhMCVVMxDTALBgNV
BAgMBFV0YWgxEjAQBgNVBAcMCVNhbHQgTGFrZTEPMA0GA1UECgwGVmVuYWZpMQ8w
DQYDVQQLDAZEZXZPcHMxGDAWBgNVBAMMD3Rlc3QudmVuZGV2LmNvbTCBnzANBgkq
hkiG9w0BAQEFAAOBjQAwgYkCgYEAqIPiGtjnxep5gQHIiDXhHpHYhr/ndwFKQ2HN
GftD3AMjMDyolSQY27w7PScTZXcuENew0zsH4iA7UsFhEGB6AIoelBWxiWc1SYRN
slIgsSxsRlksJowFcL/E40qkmL0TerI2vq829jF3XY6X1E3e1OXo0kbmBLwEB/xn
pfuvpt0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAMsuZogw+GE3ACQpULxxC3GFP
+3N91g79V5PBP9flBuMuNoC5sQdEFaRBYA7VAUc/0kwT9hbQsm6GO/PnuhDljkqB
2toPXTW5Okg93r0ZlTKrNWamsj3b5JQOB/dvjBx2c4VDzaD7lO0WMPaNbc0DV1Mm
5UGslmj7iZIMRmyV4Cvdq/1u3/GjjO8q7qglltYtCP79xAw78dCbhtbdFzCixJ+g
wNesasf48fL5jiH4gCwpzNij0ryhR0zglz+TsHRGVMef2CNFOw0PfkinQoaDI/Y+
e/0CZ8Cg2oudlSulDRWzFJBwiCapeRfwkLkhO/pjd0ILvBk8DFzjwCFTpi2SpQ==
-----END CERTIFICATE-----
`
	chechCertificateRSACert2 = `
-----BEGIN CERTIFICATE-----
MIICyjCCAbICCQDtS0qAZisbTjANBgkqhkiG9w0BAQsFADBmMQswCQYDVQQGEwJV
UzENMAsGA1UECAwEVXRhaDESMBAGA1UEBwwJU2FsdCBMYWtlMQ8wDQYDVQQKDAZW
ZW5hZmkxDzANBgNVBAsMBkRldk9wczESMBAGA1UEAwwJVmVuYWZpIENBMB4XDTE5
MDMxNDE4MDMwMVoXDTE5MDQxMzE4MDMwMVowbDELMAkGA1UEBhMCVVMxDTALBgNV
BAgMBFV0YWgxEjAQBgNVBAcMCVNhbHQgTGFrZTEPMA0GA1UECgwGVmVuYWZpMQ8w
DQYDVQQLDAZEZXZPcHMxGDAWBgNVBAMMD3Rlc3QudmVuZGV2LmNvbTCBnzANBgkq
hkiG9w0BAQEFAAOBjQAwgYkCgYEAo5m9VocciaEoP6tFlclhXxu6x3SDS5YEYx4r
5WW3Ibwf+H+d7I+YegSHrY//cUbdQ/ug4AAZ/Pf/IJaF/t8eY3PV3r8fIJ1C8PiT
P970Tq3L6TWIzlfqkZL3vE+w5uAd/I6AufX9h0q+rzXIb47+a1+pAQjaLNhQBuFS
2repty0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfb5V/rcEEsZ68rRaEerkvPCk
EiBMepUAzGrUFQyENiA2qoRuqKnOjhyzZ4uFiXFamiqCK0kjzUVraAYjzhGkH6AU
AxUKXh5fa9tkt0XsZCS1aTjuDYAPO2Ug62OejUoZtRjy+nGUM7dYku9syzhmQ+hK
AHu1RG+ZOtT13j3SAH0nkjEADzzsZhZWj/m5HtGQUY9ehAQhbTqn/M+aeGPxOdPt
Ys0kiIJWXXW4JpJLfwKE9VFERQdHVum0+j8dUfOfyo0clJLPcesBFQ4RRkituxnG
vDm5x5eZ/dsjYa8CcADBe/2KJBnldZW02o1/OqJ67m2Q1Y74hRTV5MGybpYx/w==
-----END CERTIFICATE-----
`
)

func TestRequest_CheckCertificate(t *testing.T) {
	rsaPrivKeyInvalid := pemRSADecode(checkCertificatePrivateKeyRSAinvalid)
	rsaPrivKeyValid := pemRSADecode(checkCertificatePrivateKeyRSAvalid)

	cases := []struct {
		request      Request
		cert         string
		valid        bool
		errorMessage string
	}{
		{Request{KeyType: KeyTypeRSA, PrivateKey: rsaPrivKeyValid}, chechCertificateRSACert, true, ""},
		{Request{KeyType: KeyTypeECDSA, PrivateKey: rsaPrivKeyValid}, chechCertificateRSACert, false, "key type"},
		{Request{KeyType: KeyTypeRSA, PrivateKey: rsaPrivKeyInvalid}, chechCertificateRSACert, false, "key modules"},
		{Request{csr: []byte(checkCertificateCSRRSA)}, chechCertificateRSACert, true, ""},
		{Request{csr: []byte(checkCertificateCSRRSA)}, chechCertificateRSACert2, false, "key modules"},
	}
	for _, c := range cases {
		err := c.request.CheckCertificate(c.cert)
		if c.valid && err != nil {
			t.Fatalf("cert should be valid but checker found error: %s", err)
		}
		if !c.valid && err == nil {
			t.Fatalf("certificate should failed but check returns that its valid")
		}
		if !c.valid && !strings.Contains(err.Error(), c.errorMessage) {
			t.Fatalf("unexpected error '%s' (should conatins %s)", err.Error(), c.errorMessage)
		}

	}
}

func TestRequest_SetCSR_and_GetCSR(t *testing.T) {
	checkCN := "setcsr.example.com"
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject.CommonName = checkCN
	pk, err := GenerateRSAPrivateKey(512)
	if err != nil {
		t.Fatalf("Error generating RSA Private Key\nError: %s", err)
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, pk)
	if err != nil {
		csr = nil
	}

	rawCsr := csr

	pemCsr := pem.EncodeToMemory(GetCertificateRequestPEMBlock(csr))
	r := Request{}

	csrs := [][]byte{rawCsr, pemCsr}
	for _, csr := range csrs {
		err = r.SetCSR(csr)
		if err != nil {
			t.Fatal(err)
		}
		gotCsr := r.GetCSR()
		block, _ := pem.Decode(gotCsr)
		cert, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		if cert.Subject.CommonName != checkCN {
			t.Fatalf("%s =! %s", cert.Subject.CommonName, checkCN)
		}
		err = r.SetCSR(pemCsr)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Got cn %s from csr %s", cert.Subject.CommonName, gotCsr)
	}

}

func pemRSADecode(priv string) *rsa.PrivateKey {
	privPem, _ := pem.Decode([]byte(priv))

	parsedKey, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		panic(err)
	}
	return parsedKey.(*rsa.PrivateKey)
}
