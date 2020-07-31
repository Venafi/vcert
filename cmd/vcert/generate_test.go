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
	"github.com/Venafi/vcert/pkg/certificate"
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

func TestGenerateCsrJsonFormat(t *testing.T) {
	t.Skip()
	//
	//	flags := getCommandFlags()
	//
	//
	//	flags.csrFile = "/Users/rvelamia/Desktop/vcertWorkingDir/cert.csr"
	//	flags.keyFile = "/Users/rvelamia/Desktop/vcertWorkingDir/cert.key"
	//	flags.csrFormat = "json"
	//	flags.noPrompt = true
	//	flags.commonName = "localhost"
	//	flags.org = "venafi"
	//	flags.orgUnits = stringSlice{"devops"}
	//	flags.keyTypeString = "rsa"
	//	kt := certificate.KeyTypeRSA
	//	flags.keyType = &kt
	//	flags.keySize = 4096
	//	flags.locality = "Merida"
	//	flags.state = "Yucatan"
	//	flags.country = "Mx"
	//
	//	key, csr, err := generateCsrForCommandGenCsr(flags, []byte(flags.keyPassword))
	//	if err != nil {
	//		t.Fatalf("%s", err)
	//	}
	//	err = writeOutKeyAndCsr(commandGenCSRName, flags, key, csr)
	//	if err != nil {
	//		t.Fatalf("%s", err)
	//	}
	//
	//	csrData, err := ioutil.ReadFile(flags.csrFile)
	//	if err != nil {
	//		t.Fatalf("%s", err)
	//	}
	//	keyData, err := ioutil.ReadFile(flags.keyFile)
	//	if err != nil {
	//		t.Fatalf("%s", err)
	//	}
	//
	//	csrStr := byteToStr(csrData)
	//	keyStr := byteToStr(keyData)
	//
	//	csrStr = strings.TrimLeft(csrStr, "{\"Certificate\":")
	//	csrStr = strings.TrimRight(csrStr, "}")
	//	keyStr = strings.TrimLeft(keyStr, "{\"PrivateKey\":")
	//	keyStr = strings.TrimRight(keyStr, "}")
	//
	//	jsonBody := "{\n" +
	//		"\"PolicyDN\" : \"rvela.test.venafi.example.com\",\n" +
	//		"\"ObjectName\" : \"rvela.demoGo\",\n" +
	//		"\"CertificateData\" : \"" + csrStr + ",\n" +
	//		"\"PrivateKeyData\" : \"" + keyStr + ",\n" +
	//		"\"Password\" : \"\",\n" +
	//		"\"CASpecificAttributes\" : \"[]\",\n" +
	//		"\"Reconcile\" : false\n" +
	//		"}"
	//
	//	//Json client
	//	client := resty.New()
	//	apiResp, err := client.R().
	//		SetHeader("Content-type", "application/json").
	//		SetAuthToken(token).
	//		SetBody(jsonBody).
	//		Post(flags.url + "/vedsdk/certificates/import")
	//
	//	fmt.Println(apiResp.Header())
}

func TestGenerateCsrJson(t *testing.T) {
	cf := getCommandFlags()

	cf.csrFormat = "json"
	cf.noPrompt = true

	key, csr := generateCsrJson(cf)

	jsonOutput := Output{}
	err := json.Unmarshal(csr, jsonOutput)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if jsonOutput.Certificate == "" {
		t.Fatalf("CSR data is empty")
	}

	err = json.Unmarshal(key, jsonOutput)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if jsonOutput.PrivateKey == "" {
		t.Fatalf("CSR data is empty")
	}
}

func TestGenerateCsrJsonSingleFile(t *testing.T) {
	return
}

func TestGenerateCsrJsonMultipleFiles(t *testing.T) {
	return
}

func generateCsrJson(cf *commandFlags) (key []byte, csr []byte) {

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
