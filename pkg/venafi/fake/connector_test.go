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
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"testing"
	"time"
)

func TestRetrieveCertificate(t *testing.T) {

	defaultZoneTag := ""
	conn := getTestConnector()
	zoneConfig, err := conn.ReadZoneConfiguration(defaultZoneTag)

	req := &certificate.Request{}
	req.Subject.CommonName = fmt.Sprintf("vcert.test%d.venafi.example.com", time.Now().Nanosecond())
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.KeyLength = 512
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req, defaultZoneTag)
	if err != nil {
		t.Fatalf("%s", err)
	}

	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootLast
	_, err = conn.RetrieveCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func getTestConnector() *Connector {
	c := NewConnector(true, nil)
	return c
}

func TestRevokeCertificate(t *testing.T) {
	var revReq = &certificate.RevocationRequest{}
	var connector = getTestConnector()
	err := connector.RevokeCertificate(revReq)
	if err == nil {
		t.Fatal("should fail with not-supported error")
	}
}

func TestReadZoneConfiguration(t *testing.T) {
	var connector = getTestConnector()
	_, err := connector.ReadZoneConfiguration("")
	if err != nil {
		t.Fatal("should return empty zone-config object")
	}
}

func TestRequestCertificate(t *testing.T) {
	var connector = NewConnector(true, nil)
	req := &certificate.Request{}
	req.Subject.CommonName = "test-mode"
	req.CsrOrigin = certificate.LocalGeneratedCSR
	req.KeyLength = 512

	err := connector.GenerateRequest(nil, req)
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	requestID, err := connector.RequestCertificate(req, "")
	if err != nil {
		t.Fatalf("error: %s", err)
	}
	if requestID == "" {
		t.Fatalf("should return non-empty pickupId")
	}
}
