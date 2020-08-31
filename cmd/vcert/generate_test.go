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
	"encoding/json"
  "github.com/Venafi/vcert/v4/pkg/certificate"
	"io/ioutil"
	t "log"
	"os"
	"testing"
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

	csrName := os.TempDir() + "csr.txt"
	keyName := os.TempDir() + "key.txt"

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
