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

package endpoint

import (
	"crypto/x509"
	"github.com/Venafi/vcert/pkg/certificate"
	"sort"
	"strings"
	"testing"
)

func TestNewZoneConfiguration(t *testing.T) {
	zc := NewZoneConfiguration()
	if zc.CustomAttributeValues == nil {
		t.Fatalf("NewZoneConfiguration() did not initialize CustomAttributeValues map")
	}
}

func TestUpdateRequestSubject(t *testing.T) {
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}

	z := getBaseZoneConfiguration()

	z.UpdateCertificateRequest(&req)

	if strings.EqualFold(req.Subject.Organization[0], z.Organization) {
		t.Fatalf("Updated request did not contain the expected Organization: '%s' -- Actual Organization: '%s'", z.Organization, req.Subject.Organization[0])
	}
	if !strings.EqualFold(req.Subject.Country[0], z.Country) {
		t.Fatalf("Updated request did not contain the expected Country: %s -- Actual Country %s", z.Country, req.Subject.Country[0])
	}
	if !strings.EqualFold(req.Subject.Province[0], z.Province) {
		t.Fatalf("Updated request did not contain the expected Province: %s -- Actual Province %s", z.Province, req.Subject.Province[0])
	}
	if !strings.EqualFold(req.Subject.Locality[0], z.Locality) {
		t.Fatalf("Updated request did not contain the expected Locality: %s -- Actual Locality %s", z.Locality, req.Subject.Locality[0])
	}

	sort.Strings(req.Subject.OrganizationalUnit)
	for _, val := range z.OrganizationalUnit {
		if sort.SearchStrings(req.Subject.OrganizationalUnit, val) >= len(req.Subject.OrganizationalUnit) {
			t.Fatalf("Updated request did not contain the expected OrganizationUnit: %s -- Actual Organizational Units %s", val, req.Subject.OrganizationalUnit)
		}
	}
	if req.SignatureAlgorithm != x509.SHA512WithRSA {
		t.Fatalf("Updated request did not contain the expected Signagure Algorithm: %v -- Actual: %v", x509.SHA512WithRSA, req.SignatureAlgorithm)
	}

	ks := req.KeyLength
	if ks != 4096 {
		t.Fatalf("1 getRequestKeySize did not return the expected value of 4096 -- Actual value %d", ks)
	}

	z.AllowedKeyConfigurations = nil
	z.KeySizeLocked = false
	req.KeyLength = 0
	z.UpdateCertificateRequest(&req)
	ks = req.KeyLength
	if ks != 2048 {
		t.Fatalf("2 getRequestKeySize did not return the expected value of %d -- Actual value %d", 2048, ks)
	}

	z.AllowedKeyConfigurations = []AllowedKeyConfiguration{AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048, 4096}}}
	z.KeySizeLocked = false
	req.KeyType = certificate.KeyTypeRSA
	req.KeyLength = 2048
	z.UpdateCertificateRequest(&req)
	ks = req.KeyLength
	if ks != 2048 {
		t.Fatalf("3 getRequestKeySize did not return the expected value of 2048 -- Actual value %d", ks)
	}

	req.KeyLength = 0
	z.UpdateCertificateRequest(&req)
	ks = req.KeyLength
	if ks != 4096 {
		t.Fatalf("4 getRequestKeySize did not return the expected value of 4096 -- Actual value %d", ks)
	}
}

func TestUpdateRequestSubjectMostlyEmpty(t *testing.T) {
	req := certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"

	z := getBaseZoneConfiguration()

	z.UpdateCertificateRequest(&req)

	if req.Subject.Organization[0] != z.Organization {
		t.Fatalf("Updated request did not contain the expected Organization: %s -- Actual Organization: %s", z.Organization, req.Subject.Organization[0])
	}
	if !strings.EqualFold(req.Subject.Country[0], z.Country) {
		t.Fatalf("Updated request did not contain the expected Country: %s -- Actual Country %s", z.Country, req.Subject.Country[0])
	}
	if !strings.EqualFold(req.Subject.Province[0], z.Province) {
		t.Fatalf("Updated request did not contain the expected Province: %s -- Actual Province %s", z.Province, req.Subject.Province[0])
	}
	if !strings.EqualFold(req.Subject.Locality[0], z.Locality) {
		t.Fatalf("Updated request did not contain the expected Locality: %s -- Actual Locality %s", z.Locality, req.Subject.Locality[0])
	}

	sort.Strings(req.Subject.OrganizationalUnit)
	for _, val := range z.OrganizationalUnit {
		if sort.SearchStrings(req.Subject.OrganizationalUnit, val) >= len(req.Subject.OrganizationalUnit) {
			t.Fatalf("Updated request did not contain the expected OrganizationUnit: %s -- Actual Organizational Units %s", val, req.Subject.OrganizationalUnit)
		}
	}
	if req.SignatureAlgorithm != x509.SHA512WithRSA {
		t.Fatalf("Updated request did not contain the expected Signagure Algorithm: %v -- Actual: %v", x509.SHA512WithRSA, req.SignatureAlgorithm)
	}
}

func TestGoodValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc"}
	req.Subject.OrganizationalUnit = []string{"Engineering", "Quality Assurance"}
	req.Subject.Locality = []string{"SLC"}
	req.Subject.Province = []string{"UT"}
	req.Subject.Country = []string{"US"}
	req.DNSNames = []string{"vcert.test.vfidev.com", "vcert.test1.vfidev.com"}
	req.KeyType = certificate.KeyTypeRSA
	req.KeyLength = 4096

	z := getBaseZoneConfiguration()
	z.SubjectCNRegexes = []string{".*.vfidev.com", ".*.venafi.com"}
	z.SubjectORegexes = []string{"Venafi.*"}
	z.SubjectOURegexes = []string{".*"}
	z.SubjectLRegexes = []string{"(SLC|Salt Lake City)"}
	z.SubjectSTRegexes = []string{"(UT|Utah)"}
	z.SubjectCRegexes = []string{"US"}
	z.SANRegexes = []string{".*.vfidev.com"}

	err := z.ValidateCertificateRequest(req)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestBadCNValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.Subject.CommonName = "vcert.test.bonjo.com"

	z := getBaseZoneConfiguration()
	z.SubjectCNRegexes = []string{".*.vfidev.com", ".*.venafi.com"}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("CN should not have matched")
	}
}

func TestBadOValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.Subject.Organization = []string{"Bonjo Org"}

	z := getBaseZoneConfiguration()
	z.SubjectORegexes = []string{"Venafi.*"}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("O should not have matched")
	}
}

func TestBadOUValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.Subject.OrganizationalUnit = []string{"Oddballs", "Squares"}

	z := getBaseZoneConfiguration()
	z.SubjectOURegexes = []string{"Venafi", "Venafi, Inc."}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("OU should not have matched")
	}
}

func TestBadLValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.Subject.Locality = []string{"Not in SLC"}

	z := getBaseZoneConfiguration()
	z.SubjectLRegexes = []string{"^(SLC|Salt Lake City)"}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("L should not have matched")
	}
}

func TestBadSTValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.Subject.Province = []string{"CO"}

	z := getBaseZoneConfiguration()
	z.SubjectSTRegexes = []string{"(UT|Utah)"}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("ST should not have matched")
	}
}

func TestBadCValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.Subject.Country = []string{"USA"}

	z := getBaseZoneConfiguration()
	z.SubjectCRegexes = []string{"^US$"}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("C should not have matched")
	}
}

func TestBadSANValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.DNSNames = []string{"vcert.test.venafi.com", "vcert.test1.venafi.com"}

	z := getBaseZoneConfiguration()
	z.SANRegexes = []string{".*.vfidev.com"}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("SANs should not have matched")
	}
}

func TestBadKeyTypeValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.KeyType = certificate.KeyTypeECDSA

	z := getBaseZoneConfiguration()
	z.AllowedKeyConfigurations = []AllowedKeyConfiguration{AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048, 4096}}}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("Key type ECDSA should not have been ok")
	}
}

func TestBadKeySizeValiateRequest(t *testing.T) {
	req := new(certificate.Request)
	req.KeyType = certificate.KeyTypeRSA
	req.KeyLength = 8192

	z := getBaseZoneConfiguration()
	z.AllowedKeyConfigurations = []AllowedKeyConfiguration{AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048, 4096}}}

	err := z.ValidateCertificateRequest(req)
	if err == nil {
		t.Fatalf("Key size 8192 should not have been ok")
	}
}

func getBaseZoneConfiguration() *ZoneConfiguration {
	z := ZoneConfiguration{}
	z.Organization = "Venafi, Inc."
	z.OrganizationLocked = false
	z.OrganizationalUnit = []string{"Engineering", "Automated Tests"}
	z.Country = "US"
	z.CountryLocked = false
	z.Province = "Utah"
	z.ProvinceLocked = true
	z.Locality = "SLC"
	z.LocalityLocked = true
	z.AllowedKeyConfigurations = []AllowedKeyConfiguration{AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{2048, 4096}}}
	z.KeySizeLocked = true
	z.HashAlgorithm = x509.SHA512WithRSA
	return &z
}
