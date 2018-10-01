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

package fake

import (
	"github.com/Venafi/vcert/pkg/certificate"
	"testing"
)

func TestGenerateRequest(t *testing.T) {
	var req certificate.Request

	fake := Connector{}

	req = certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.CsrOrigin = certificate.LocalGeneratedCSR
	req.KeyLength = 512

	err := fake.GenerateRequest(nil, &req)
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if len(req.CSR) == 0 {
		t.Fatalf("should generaet CSR")
	}

	req = certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.CsrOrigin = certificate.UserProvidedCSR
	err = fake.GenerateRequest(nil, &req)
	if err == nil {
		t.Fatalf("should fail without user-provided CSR")
	}

	req = certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.CsrOrigin = certificate.ServiceGeneratedCSR
	err = fake.GenerateRequest(nil, &req)
	if err != nil || len(req.CSR) > 0 {
		t.Fatalf("should do nothing")
	}
}
