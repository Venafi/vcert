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

package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/util"
)

var (
	cert = `-----BEGIN CERTIFICATE-----
MIICljCCAX6gAwIBAgIRAO8Qp6LUsgVDQrxHXX1LUV4wDQYJKoZIhvcNAQENBQAw
gYAxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRcwFQYDVQQHDA5TYWx0IExh
a2UgQ2l0eTEPMA0GA1UECgwGVmVuYWZpMRswGQYDVQQLDBJOT1QgRk9SIFBST0RV
Q1RJT04xGzAZBgNVBAMMElZDZXJ0IFRlc3QgTW9kZSBDQTAeFw0xODA4MDUwMTE4
MjVaFw0xODExMDMwMTE4MjVaMAwxCjAIBgNVBAMTAXEwXDANBgkqhkiG9w0BAQEF
AANLADBIAkEAz5jYYiZbUvxbsaboaoJBUnPdFf6bNwux1Ip3tXRcNQ4j4LIZVn+l
EcnISnOzAGxjGTnixwlZ7TDX2GupqkuxZQIDAQABo0YwRDATBgNVHSUEDDAKBggr
BgEFBQcDATAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFM6kRQ7y19Js+AIz2+Ob
Sxmr5vAHMA0GCSqGSIb3DQEBDQUAA4IBAQBjQB1LiSx0eh0NK3uA9/lbFHfM26D/
FE/CAupvCaSJNi7sc5P35mYAcbVjjPhKG9k+Gn9LXxtbF5O1ipYCLcuYRFGLh7kM
Nd4DqHPZRaIcxXQMYGHZ26omPgx9m7GvPuFFNhtxBSNLPBDoGW2XuUearObxgIWV
IGfez+BB1qWlRNT/aF0qqPCSvYsN5oX79Int8f8wTT4PSmYd9gxOgDq5JlAgvYw5
BfM/og0jia3XsLC25gILLbj3ozkvTndKOF0KDqYIW0kCEE9DiBlC84hIybpgILL7
T9Aufk2CABqo6tnwIW1GC4qf/6xsO6qnU2yGpmds8s1JZqeZ+jC3Dov3
-----END CERTIFICATE-----`

	PK = `-----BEGIN RSA PRIVATE KEY-----
MIIBPAIBAAJBAPTwgD/aLq+NvXdvlKB8McWvB9pUPwlX3aDQBYJiyQ4Cl9qMpwPr
n0GZ6So6+52MFVGDNjVTe6CvoIXweCnsWGUCAwEAAQJBAJp/YMXl33DIXOwLK5qW
++YPY0qpvSEtlRQsYm091kfIyv03JXoa3Gqirr7ualBH/V69UvjmEmioduuamPTV
K3kCIQD/hn/uB+NJTmOwtE+YIyp/ufJzszBoxL8RsN7kA19l1wIhAPVk97ynwhfd
GLWSKgDCfSUJ5+t0PwUkxknE67MkpHQjAiArAGKFF1S7oHKMaTu/2aMsTYmsyOoL
p5iUDJTmAF9MjwIhAOjDwQm9xqmEGu//mL/nu3TqlIYOWcizPTK0Cy59z1ApAiEA
xo1KNfHqzyDxovWlYL08R8omt0znO8Ljnq+8DX6aBCI=
-----END RSA PRIVATE KEY-----`

	encPK = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1fe24235e016f1c40adbdca0a19cf9d6

B2Fu5Hs31UgSIL689SPisaEpabz+QdmXVnTO1/Ax6so9AN00+HgpMTBDF7t6XqZ6
nCJ24Rlkrb3LJL1yvTX3isRS0ab7uLGh9h6VYX7SpjAvFNsEeY79JyZfHMFBjkyg
IEBwwR1Gyp9MOyUHgaku0cUfcGkRPjWQ/8c/VHUZe5KZ3yBh4lHCGYZoBnDLZfte
Li8WWx+StyDKuCVtt9c/wQkaTgAdWjxe6Sowt2nuE7uJyu5PXSsvqi/eohqh9mE7
Al3nqH2F3QSbPUMTIV6ar6uEFiOIjp6BSPRTOUNgigqlPY51KJVZboKapFHy23Sy
JdT1+vbzuKt50CcU6uqaYxBbU7lpwT61Gvw8bnrLhXVrOcs4Oi2Cc8nt+5qt+++y
ozO8ZQRvOf56AHRMUBmVR4ouRrP0ABOfxSGWjhTBqCgtqeI/+FNDwxpQP/4kiXoT
-----END RSA PRIVATE KEY-----`

	encPKForJKS = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,8DCD95996B09B376940FDDF85C339EAB

3fOby1I1A5uKeSl2mrib6P8lh5cvZrbMDrKhzeDeOSZNa0ea+XLyJpyjwFX07STt
ExAZUkqznVBdv4qhGBo1ubhsDDzc5+A/6cyo/MFyuT00wZpGqW9iq/EXXO9cIQ5c
lE1CnJaNeH/IQIVMmJ5zchlxL136B1N0TrbxyLMSwYZz6vTDLXyX6+UCaUa6Jvkz
6BbrY01LGYng4KkeTZRWLnY+srCWat3bKf8qT/cDmanspg6resBB7jJNYgms8Axu
c44bb3ha8NmF8cJYxvXEjJgLqaKyY7ymtrnvDBjOddurN6Ksh3O2zDGg5yfN5Y9A
oR2vBkvZgKipE75kh10j65DjkKrTQ8NPeDqCgwzOEdM3oQ4hiA0Wi7g9ea3sO8n7
9oQr1O184Joo89+KHVShSDGDeCyMOpSOvtqDgnmaHUrR93XCH5YnEgaTw34McNpA
-----END RSA PRIVATE KEY-----`

	ec = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB6apqEMa3ByjYQPfLLsyNJNo6rmqt8Niyy6w6f0qf8GZ8052oGq9v
7uZBhm8TcmowAYhc2OzKXtC+YH7Xr3Rd//egBwYFK4EEACOhgYkDgYYABAB4M4U4
QFKANzBA8+yIv02LJh90j4ydHadIZIFyNazG39du63CLcIPW57bec/uIUlAVG+ns
27yz12Xs5rv+Fow8ngDC0dva6HY57df+RNHBI0GzChDLSzWSeEbsQLtkUfwVt172
QurQ9gqfWxInA/VHyQ8fNHaKv+Y3tH5efZBi2U3+iQ==
-----END EC PRIVATE KEY-----`

	caCert = `-----BEGIN CERTIFICATE-----
MIID1TCCAr2gAwIBAgIJAIOVTvMIMD7OMA0GCSqGSIb3DQEBCwUAMIGAMQswCQYD
VQQGEwJVUzENMAsGA1UECAwEVXRhaDEXMBUGA1UEBwwOU2FsdCBMYWtlIENpdHkx
DzANBgNVBAoMBlZlbmFmaTEbMBkGA1UECwwSTk9UIEZPUiBQUk9EVUNUSU9OMRsw
GQYDVQQDDBJWQ2VydCBUZXN0IE1vZGUgQ0EwHhcNMTgwMzI3MTAyNTI5WhcNMzgw
MzIyMTAyNTI5WjCBgDELMAkGA1UEBhMCVVMxDTALBgNVBAgMBFV0YWgxFzAVBgNV
BAcMDlNhbHQgTGFrZSBDaXR5MQ8wDQYDVQQKDAZWZW5hZmkxGzAZBgNVBAsMEk5P
VCBGT1IgUFJPRFVDVElPTjEbMBkGA1UEAwwSVkNlcnQgVGVzdCBNb2RlIENBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0BobDKthxG5SuMfAp2heyDQN
/IL9NTEnFJUUl/CkLEQTSQT68M9US7TCxi+FOizIoev2k4Nkovgk7uM0q94aygbh
cHyTTL64uphHwcClu99ZQ6DIwzDH2gREsLWfj+KXw4bPsne+5tGxv2+0jG2at5or
p/nOQWYD1C1HB6ZQqvP3PypDjou7Uh+Y00bOfXkbYWr8GkX4XAL6UtC0jUnsBEZX
CuwO1BlIIoKNokhOV7Jcb3l/jurjzVWfem+tqwYb/Tkj6MI1YBqt6Yy2EsGsoAv1
E5/IGcjSQnLEqDWhpY0s2fA4o+bAMzyakDFKJoQbF982QhS2fT+d87vQlnMi1QID
AQABo1AwTjAdBgNVHQ4EFgQUzqRFDvLX0mz4AjPb45tLGavm8AcwHwYDVR0jBBgw
FoAUzqRFDvLX0mz4AjPb45tLGavm8AcwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0B
AQsFAAOCAQEAWbRgS1qUyGMh3ToJ060s5cdoKzyx/ji5pRPXRxrmzzSxP+dlKX7h
AKUgYOV9FU/k2f4C7TeCZSsir20x8fKRg4qs6r8vHTcWnkC6A08SNlT5kjyJl8vt
qQTEsemnyBFis8ZFUfYdmNYqZXuWSb7ZBfNkR7qMVna8A87NyEmTtlTBkZYSTOaB
NRuOli+/6akXg/OW/GfVUD11D413CtZsWNzKaxj1WH88mjBYwQx2pGRzMWHfWBka
f6ZUnA9hhqxO4CHqQWmKPHftbGscwx5yg/J6J7TfG+rYd5ZVVhrr2un2xpOTctjO
lriDCQa4FOwP9/x1OJRXEsSl5YFqBppX5A==
-----END CERTIFICATE-----`

	chain = []string{
		caCert, caCert,
	}
)

func TestPKCS12withEncPK(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  encPK,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"pkcs12",
			"",
			"",
			certificate.ChainOptionFromString(""),
			"/tmp/TestPKCS12withEncPK",
			"",
			"",
			"",
			"",
			"",
			"asdf",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}

	//confirming that the PKCS12 file contains the same PK, Cert and Chain as the original data
	validateGeneratedPKCS12IsCorrect(t, result)
}

func TestPKCS12withPlainPK(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  PK,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"pkcs12",
			"",
			"",
			certificate.ChainOptionFromString(""),
			"/tmp/TestPKCS12withPlainPK",
			"",
			"",
			"",
			"",
			"",
			"",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}

	//confirming that the PKCS12 file contains the same PK, Cert and Chain as the original data
	validateGeneratedPKCS12IsCorrect(t, result)
}

func TestPKCS12withPlainEcPK(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  ec,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"pkcs12",
			"",
			"",
			certificate.ChainOptionFromString(""),
			"/tmp/TestPKCS12withPlainEcPK",
			"",
			"",
			"",
			"",
			"",
			"",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}

	//confirming that the PKCS12 file contains the same PK, Cert and Chain as the original data
	validateGeneratedPKCS12IsCorrect(t, result)
}

func TestLegacyPKCS12withEncPK(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  encPK,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"legacy-pkcs12",
			"",
			"",
			certificate.ChainOptionFromString(""),
			"/tmp/TestLegacyPKCS12withEncPK",
			"",
			"",
			"",
			"",
			"",
			"asdf",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}

	//confirming that the PKCS12 file contains the same PK, Cert and Chain as the original data
	validateGeneratedPKCS12IsCorrect(t, result)
}

func TestLegacyPKCS12withPlainPK(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  PK,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"legacy-pkcs12",
			"",
			"",
			certificate.ChainOptionFromString(""),
			"/tmp/TestLegacyPKCS12withPlainPK",
			"",
			"",
			"",
			"",
			"",
			"",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}

	//confirming that the PKCS12 file contains the same PK, Cert and Chain as the original data
	validateGeneratedPKCS12IsCorrect(t, result)
}

func TestLegacyPKCS12withPlainEcPK(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  ec,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"legacy-pkcs12",
			"",
			"",
			certificate.ChainOptionFromString(""),
			"/tmp/TestLegacyPKCS12withPlainEcPK",
			"",
			"",
			"",
			"",
			"",
			"",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}

	//confirming that the PKCS12 file contains the same PK, Cert and Chain as the original data
	validateGeneratedPKCS12IsCorrect(t, result)
}

func TestJKSWithEncPKWithoutJKSPass(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  encPKForJKS,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"jks",
			"jksAlias",
			"",
			certificate.ChainOptionFromString(""),
			"/tmp/TestJKSWithEncPKAndJKSPass",
			"",
			"",
			"",
			"",
			"",
			"password",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}
}

func TestJKSWithEncPKAndJKSPass(t *testing.T) {
	result := &Result{
		&certificate.PEMCollection{
			Certificate: cert,
			PrivateKey:  encPKForJKS,
			Chain:       chain,
		},
		"==pickup-id==",
		&Config{
			"enroll",
			"jks",
			"jksAlias",
			"123456",
			certificate.ChainOptionFromString(""),
			"/tmp/TestJKSWithEncPKAndJKSPass",
			"",
			"",
			"",
			"",
			"",
			"password",
		},
	}
	err := result.Flush()

	if err != nil {
		t.Fatal("Failed to output the results: ", err)
	}
}

func validateGeneratedPKCS12IsCorrect(t *testing.T, result *Result) {
	//reading the generated PCKS12 file in order to get the PrivateKey, Cert and ChainCert to validate they are equals
	// to the original
	bytes, err := os.ReadFile(result.Config.AllFile)
	if err != nil {
		t.Fatal("Failed to read the output results: ", err)
	}

	//decoding the PKCS12 data
	privateKeyDecoded, certDecoded, caCertsDecoded, err := pkcs12.DecodeChain(bytes, result.Config.KeyPassword)

	if assert.NoError(t, err) {
		assert.NotNil(t, privateKeyDecoded)
		assert.NotNil(t, certDecoded)
		assert.NotNil(t, caCertsDecoded)

		//getting the original PK
		var privKeyOriginal interface{}
		privKeyOriginal, err = parsePKInPKCS1ToPrivateKey(result.Pcc.PrivateKey, result.Config.KeyPassword)
		if err != nil {
			t.Fatal("Failed to parse the original private key: ", err)
		}

		//asserting the original PK and the decoded PK from the generated PKCS12 are the same
		assert.Equal(t, privKeyOriginal, privateKeyDecoded)

		//getting the original Cert
		var certOriginal *x509.Certificate
		certOriginal, err = parseCertificate(result.Pcc.Certificate)
		if err != nil {
			t.Fatal("Failed to parse the original certificate: ", err)
		}

		//asserting the original Cert and the decoded Cert from the generated PKCS12 are the same
		assert.Equal(t, certOriginal, certDecoded)

		//getting the original CAChain
		var chainList []*x509.Certificate
		chainList, err = parseChain(result.Pcc.Chain)
		if err != nil {
			t.Fatal("Failed to parse the original chain of certificates: ", err)
		}

		//asserting the original CAChain and the decoded CAChain from the generated PKCS12 are the same
		assert.Equal(t, chainList, caCertsDecoded)
	}
}

func parsePKInPKCS1ToPrivateKey(encPK string, keyPassword string) (interface{}, error) {
	privateKeyPEM, _ := pem.Decode([]byte(encPK))
	if privateKeyPEM == nil {
		return nil, errors.New("it was not possible to decode the private key")
	}
	var privateBytes []byte
	if keyPassword != "" {
		var err error
		privateBytes, err = util.X509DecryptPEMBlock(privateKeyPEM, []byte(keyPassword))
		if err != nil {
			return nil, err
		}
	} else {
		privateBytes = privateKeyPEM.Bytes
	}

	if privateKeyPEM.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(privateBytes)
	} else {
		// then it's considered as RSA Private Key
		return x509.ParsePKCS1PrivateKey(privateBytes)
	}
}

func parseCertificate(certString string) (*x509.Certificate, error) {
	certPEMBlock, _ := pem.Decode([]byte(certString))
	if certPEMBlock == nil || certPEMBlock.Type != "CERTIFICATE" {
		return nil, errors.New("it was not possible to decode the certificate")
	}
	return x509.ParseCertificate(certPEMBlock.Bytes)
}

func parseChain(chain []string) ([]*x509.Certificate, error) {
	var chainList []*x509.Certificate
	for _, chainCert := range chain {
		certPEMBlock, _ := pem.Decode([]byte(chainCert))
		if certPEMBlock == nil {
			return nil, errors.New("it was not possible to decode the CA certificate")
		}
		parsedCert, err := x509.ParseCertificate(certPEMBlock.Bytes)
		if err != nil {
			return nil, err
		}
		chainList = append(chainList, parsedCert)
	}

	return chainList, nil
}
