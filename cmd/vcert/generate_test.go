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
	"github.com/Venafi/vcert/pkg/certificate"
	"io/ioutil"
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
	err = writeOutKeyAndCsr(cf, key, csr)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func getCommandFlags() *commandFlags {
	cf := genCsrParams

	cf.commonName = "vcert.test.vfidev.com"
	cf.org = "Venafi"
	cf.orgUnits = []string{"Engineering", "Unit Testing"}
	cf.country = "US"
	cf.keyType = certificate.KeyTypeECDSA
	cf.keyCurve = certificate.EllipticCurveP384

	return &cf
}
