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

package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	t "log"
	"os"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

func TestGenerateCsrForCommandGenCsr(t *testing.T) {
	cf := getCommandFlags()

	key, csr, err := generateCsrForCommandGenCsr(cf, []byte("pass"))
	if err != nil {
		t.Fatalf("%s", err)
	}
	if key == nil {
		t.Fatalf("Key should not be nil")
	}
	if csr == nil {
		t.Fatalf("CSR should not be nil")
	}
}

func TestWriteOutKeyAndCsr(t *testing.T) {
	cf := getCommandFlags()
	key, csr, err := generateCsrForCommandGenCsr(cf, []byte("pass"))
	if err != nil {
		t.Fatalf("%s", err)
	}
	if key == nil {
		t.Fatalf("Key should not be nil")
	}
	if csr == nil {
		t.Fatalf("CSR should not be nil")
	}
	temp, err := ioutil.TempFile(os.TempDir(), "vcertTest")
	if err != nil {
		t.Fatalf("%s", err)
	}
	defer os.Remove(temp.Name())
	fileName := temp.Name()
	temp.Close()
	cf.file = fileName
	err = writeOutKeyAndCsr(commandGenCSRName, cf, key, csr)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestGenerateCsrForCommandGenCsrMLDSA(t *testing.T) {
	cases := []struct {
		keyType  certificate.KeyType
		sigAlgo  x509.SignatureAlgorithm
		password string
	}{
		{certificate.KeyTypeMLDSA44, x509.MLDSA44, ""},
		{certificate.KeyTypeMLDSA44, x509.MLDSA44, "pass"},
		{certificate.KeyTypeMLDSA65, x509.MLDSA65, ""},
		{certificate.KeyTypeMLDSA65, x509.MLDSA65, "pass"},
		{certificate.KeyTypeMLDSA87, x509.MLDSA87, ""},
		{certificate.KeyTypeMLDSA87, x509.MLDSA87, "pass"},
	}

	for _, tc := range cases {
		name := tc.keyType.String()
		if tc.password != "" {
			name += "-encrypted"
		}
		t.Run(name, func(t *testing.T) {
			cf := getCommandFlags()
			keyType := tc.keyType
			cf.keyType = &keyType
			cf.keyCurve = certificate.EllipticCurveNotSet

			key, csr, err := generateCsrForCommandGenCsr(cf, []byte(tc.password))
			if err != nil {
				t.Fatalf("%s", err)
			}
			if key == nil {
				t.Fatalf("Key should not be nil")
			}
			if csr == nil {
				t.Fatalf("CSR should not be nil")
			}

			// The CSR must be a valid ML-DSA request with the matching parameter set.
			block, _ := pem.Decode(csr)
			if block == nil {
				t.Fatalf("failed to PEM-decode CSR")
			}
			parsed, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse CSR: %s", err)
			}
			if parsed.PublicKeyAlgorithm != x509.MLDSA {
				t.Fatalf("expected public key algorithm %s, got %s", x509.MLDSA, parsed.PublicKeyAlgorithm)
			}
			if parsed.SignatureAlgorithm != tc.sigAlgo {
				t.Fatalf("expected signature algorithm %s, got %s", tc.sigAlgo, parsed.SignatureAlgorithm)
			}
			if err := parsed.CheckSignature(); err != nil {
				t.Fatalf("CSR signature verification failed: %s", err)
			}

			// The private key must be a (possibly encrypted) PKCS#8 PEM block.
			keyBlock, _ := pem.Decode(key)
			if keyBlock == nil {
				t.Fatalf("failed to PEM-decode private key")
			}
			wantType := "PRIVATE KEY"
			if tc.password != "" {
				wantType = "ENCRYPTED PRIVATE KEY"
			}
			if keyBlock.Type != wantType {
				t.Fatalf("expected key PEM type %q, got %q", wantType, keyBlock.Type)
			}
		})
	}
}

func getCommandFlags() *commandFlags {
	cf := flags

	cf.commonName = "vcert.test.vfidev.com"
	cf.org = "Venafi"
	cf.orgUnits = []string{"Engineering", "Unit Testing"}
	cf.country = "US"
	keyType := certificate.KeyTypeECDSA
	cf.keyType = &keyType
	cf.keyCurve = certificate.EllipticCurveP384

	return &cf
}

func TestGenerateCsrJson(t *testing.T) {

	csrName := os.TempDir() + fmt.Sprintf("%ccsr.txt", os.PathSeparator)
	keyName := os.TempDir() + fmt.Sprintf("%ckey.txt", os.PathSeparator)

	cf := getCommandFlags()
	cf.csrFormat = "json"
	cf.noPrompt = true
	cf.csrFile = csrName
	cf.keyFile = keyName

	key, csr := generateCsr(cf)

	err := writeOutKeyAndCsr(commandGenCSRName, cf, key, csr)
	if err != nil {
		t.Fatalf("%s", err)
	}

	//Reads the csr file to validate the json format
	csrData, err := ioutil.ReadFile(csrName)
	if err != nil {
		t.Fatalf("%s", err)
	}
	csrOutput := Output{}
	err = json.Unmarshal(csrData, &csrOutput)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if csrOutput.CSR == "" {
		t.Fatalf("CSR data is not in expected format : JSON")
	}

	//Reads the private key file to validate the json format
	keyData, err := ioutil.ReadFile(keyName)
	if err != nil {
		t.Fatalf("%s", err)
	}
	keyOutput := Output{}
	err = json.Unmarshal(keyData, &keyOutput)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if keyOutput.PrivateKey == "" {
		t.Fatalf("Private key data is not in expected format : JSON")
	}
	return
}

func generateCsr(cf *commandFlags) (key []byte, csr []byte) {

	key, csr, err := generateCsrForCommandGenCsr(cf, []byte(cf.keyPassword))
	if err != nil {
		t.Fatalf("%s", err)
	}
	if key == nil {
		t.Fatalf("Key should not be nil")
	}
	if csr == nil {
		t.Fatalf("CSR should not be nil")
	}
	return
}
