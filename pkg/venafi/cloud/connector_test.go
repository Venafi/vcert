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

package cloud

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/verror"
	"github.com/Venafi/vcert/v5/test"
)

var ctx *test.Context

func init() {
	ctx = test.GetEnvContext()
	// http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if ctx.CloudAPIkey == "" {
		fmt.Println("API key cannot be empty. See Makefile")
		os.Exit(1)
	}
}

func getTestConnector(zone string) *Connector {
	url, _ := normalizeURL(ctx.CloudUrl)
	c, _ := NewConnector(url, zone, true, nil)
	return c
}

func TestPing(t *testing.T) {
	conn := getTestConnector("")
	err := conn.Ping()
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestAuthenticate(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestReadZoneConfiguration(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}

	conn.SetZone("d686146b-799b-4836-8ac3-f4a2d3a38934")
	_, err = conn.ReadZoneConfiguration()
	if !errors.Is(err, verror.ZoneNotFoundError) {
		t.Fatalf("Unknown zone should have resulted in an error")
	}
	testCases := []struct {
		zone       string
		zoneConfig endpoint.ZoneConfiguration
	}{
		{ctx.CloudZone, endpoint.ZoneConfiguration{
			CustomAttributeValues: make(map[string]string),
		}},
		{ctx.CloudZoneRestricted, endpoint.ZoneConfiguration{
			Organization:          "Venafi Inc.",
			OrganizationalUnit:    []string{"Integrations"},
			Country:               "US",
			Province:              "Utah",
			Locality:              "Salt Lake",
			CustomAttributeValues: make(map[string]string),
			KeyConfiguration:      &endpoint.AllowedKeyConfiguration{KeyType: certificate.KeyTypeRSA, KeySizes: []int{4096}},
		}},
	}
	for _, c := range testCases {
		conn.SetZone(c.zone)
		zoneConfig, err := conn.ReadZoneConfiguration()
		if err != nil {
			t.Fatalf("%s", err)
		}
		zoneConfig.Policy = endpoint.Policy{}
		if !reflect.DeepEqual(*zoneConfig, c.zoneConfig) {
			t.Fatalf("zone config for zone %s is not as expected \nget:    %+v \nexpect: %+v", c.zone, *zoneConfig, c.zoneConfig)
		}
	}

}

func TestRequestCertificate(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRequestCertificateED25519WithValidation(t *testing.T) {
	conn := getTestConnector(ctx.VAASzoneEC)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}

	req := certificate.Request{}
	req.Subject.CommonName = test.RandSpecificCN("vfidev.com")
	req.Subject.Organization = []string{"Venafi Inc."}
	req.Subject.OrganizationalUnit = []string{"Integrations"}
	req.Subject.Locality = []string{"Salt Lake"}
	req.Subject.Province = []string{"Utah"}
	req.Subject.Country = []string{"US"}
	req.KeyType = certificate.KeyTypeED25519

	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}

	err = zoneConfig.ValidateCertificateRequest(&req)
	if err != nil {
		t.Fatalf("could not validate certificate request: %s", err)
	}

	zoneConfig.UpdateCertificateRequest(&req)

	err = conn.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRequestCertificateED25519WithPolicyValidation(t *testing.T) {
	conn := getTestConnector(ctx.VAASzoneEC)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}

	req := certificate.Request{}
	req.Subject.CommonName = test.RandSpecificCN("vfidev.com")
	req.Subject.Organization = []string{"Venafi Inc."}
	req.Subject.OrganizationalUnit = []string{"Integrations"}
	req.Subject.Locality = []string{"Salt Lake"}
	req.Subject.Province = []string{"Utah"}
	req.Subject.Country = []string{"US"}
	req.KeyType = certificate.KeyTypeED25519

	policy, err := conn.ReadPolicyConfiguration()
	if err != nil {
		t.Fatalf("could not read policy config certificate request: %s", err)
	}

	err = policy.ValidateCertificateRequest(&req)
	if err != nil {
		t.Fatalf("could not validate certificate request from policy: %s", err)
	}

	err = conn.GenerateRequest(nil, &req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRequestCertificateWithUsageMetadata(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}

	location := certificate.Location{
		Instance: "vcert-sdk",
	}
	req.Location = &location

	err = conn.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRequestCertificateWithValidityHours(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}

	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}

	nrHours := 144
	req.ValidityHours = nrHours
	req.IssuerHint = util.IssuerHintMicrosoft

	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}

	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootLast

	pcc, _ := certificate.NewPEMCollection(nil, nil, nil)
	startTime := time.Now()
	for {

		pcc, err = conn.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}

	certValidUntil := cert.NotAfter.Format("2006-01-02")

	//need to convert local date on utc, since the certificate' NotAfter value we got on previous step, is on utc
	//so for comparing them we need to have both dates on utc.
	loc, _ := time.LoadLocation("UTC")
	expectedValidDate := time.Now().Add(time.Duration(nrHours) * time.Hour).In(loc).Format("2006-01-02")

	if expectedValidDate != certValidUntil {
		t.Fatalf("Expiration date is different than expected, expected: %s, but got %s: ", expectedValidDate, certValidUntil)
	}

}

func TestRequestCertificateWithValidityDuration(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}

	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}

	validDuration := 144 * time.Hour
	req.ValidityDuration = &validDuration
	req.IssuerHint = util.IssuerHintMicrosoft

	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}

	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootLast

	pcc, _ := certificate.NewPEMCollection(nil, nil, nil)
	startTime := time.Now()
	for {

		pcc, err = conn.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}

	certValidUntil := cert.NotAfter.Format("2006-01-02")

	//need to convert local date on utc, since the certificate' NotAfter value we got on previous step, is on utc
	//so for comparing them we need to have both dates on utc.
	loc, _ := time.LoadLocation("UTC")
	expectedValidDate := time.Now().Add(validDuration).In(loc).Format("2006-01-02")

	if expectedValidDate != certValidUntil {
		t.Fatalf("Expiration date is different than expected, expected: %s, but got %s: ", expectedValidDate, certValidUntil)
	}

}

func TestRetrieveCertificate(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootLast

	pcc, _ := certificate.NewPEMCollection(nil, nil, nil)
	startTime := time.Now()
	for {

		pcc, err = conn.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if req.Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("Retrieved certificate did not contain expected CN.  Expected: %s -- Actual: %s", req.Subject.CommonName, cert.Subject.CommonName)
	}

	p, _ = pem.Decode([]byte(pcc.Chain[0]))
	cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if !cert.IsCA || fmt.Sprintf("%v", cert.Subject) == fmt.Sprintf("%v", cert.Issuer) {
		t.Fatalf("Expected Intermediate Root Certificate first, instead got Subject: %v -- Issuer %v", cert.Subject, cert.Issuer)
	}
}

func TestRetrieveCertificateRootFirst(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootFirst

	startTime := time.Now()
	pcc, _ := certificate.NewPEMCollection(nil, nil, nil)
	for {
		pcc, err = conn.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	if len(pcc.Chain) <= 0 {
		t.Fatalf("Chain Option was root to be first, chain count is %d", len(pcc.Chain))
	}
	p, _ := pem.Decode([]byte(pcc.Chain[0]))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if !cert.IsCA || fmt.Sprintf("%v", cert.Subject) != fmt.Sprintf("%v", cert.Issuer) {
		t.Fatalf("Expected Root Certificate first, instead got Subject: %v -- Issuer %v", cert.Subject, cert.Issuer)
	}

	p, _ = pem.Decode([]byte(pcc.Certificate))
	cert, err = x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if req.Subject.CommonName != cert.Subject.CommonName {
		t.Fatalf("Retrieved certificate did not contain expected CN.  Expected: %s -- Actual: %s", req.Subject.CommonName, cert.Subject.CommonName)
	}
}

func TestGetCertificateStatus(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	reqId, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}

	_, err = conn.getCertificateStatus(reqId)
	if err != nil {
		t.Fatalf("failed to get certificate request status: %s", err)
	}

	invalidCertificateRequestId := "42424242-63a0-11e8-b5a3-f186be5c5fab"
	_, err = conn.getCertificateStatus(invalidCertificateRequestId)
	if err == nil {
		t.Fatalf("it should return error when there is not such request found")
	}
}

func TestRenewCertificate(t *testing.T) {
	t.Skip() //todo: remove if condor team fix bug. check after 2020.04
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}

	renewTooEarly := &certificate.RenewalRequest{CertificateDN: pickupID}
	_, err = conn.RenewCertificate(renewTooEarly)
	if err == nil {
		t.Fatal("it should return error on attempt to renew a certificate that is not issued yet")
	}

	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootFirst
	startTime := time.Now()
	pcc, _ := certificate.NewPEMCollection(nil, nil, nil)
	for {
		pcc, err = conn.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("%s", err)
	}

	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}
	fp := sha1.Sum(cert.Raw)
	fingerprint := strings.ToUpper(hex.EncodeToString(fp[:]))
	t.Logf("CERT: %s\n", pcc.Certificate)
	t.Logf("FINGERPRINT: %s\n", fingerprint)

	// time to renew
	renewByFingerprint := &certificate.RenewalRequest{Thumbprint: strings.ToUpper(fingerprint)}
	reqId3, err := conn.RenewCertificate(renewByFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("requested renewal for %s, will pickup by %s", fingerprint, reqId3)

	renewByCertificateDN := &certificate.RenewalRequest{CertificateDN: reqId3}
	reqId1, err := conn.RenewCertificate(renewByCertificateDN)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("requested renewal for %s, will pickup by %s", pickupID, reqId1)

}

func TestRenewCertificateWithUsageMetadata(t *testing.T) {
	t.Skip() //todo: remove if condor team fix bug. check after 2020.04
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}

	location := certificate.Location{
		Instance: "vcert-sdk",
	}
	req.Location = &location

	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}

	renewTooEarly := &certificate.RenewalRequest{CertificateDN: pickupID}
	renewTooEarly.CertificateRequest.Location = &location

	_, err = conn.RenewCertificate(renewTooEarly)
	if err == nil {
		t.Fatal("it should return error on attempt to renew a certificate that is not issued yet")
	}

	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootFirst
	startTime := time.Now()
	pcc, _ := certificate.NewPEMCollection(nil, nil, nil)
	for {
		pcc, err = conn.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("%s", err)
	}

	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}
	fp := sha1.Sum(cert.Raw)
	fingerprint := strings.ToUpper(hex.EncodeToString(fp[:]))
	t.Logf("CERT: %s\n", pcc.Certificate)
	t.Logf("FINGERPRINT: %s\n", fingerprint)

	// time to renew
	renewByFingerprint := &certificate.RenewalRequest{Thumbprint: strings.ToUpper(fingerprint)}
	renewByFingerprint.CertificateRequest.Location = &location
	reqId3, err := conn.RenewCertificate(renewByFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("requested renewal for %s, will pickup by %s", fingerprint, reqId3)

	renewByCertificateDN := &certificate.RenewalRequest{CertificateDN: reqId3}
	renewByCertificateDN.CertificateRequest.Location = &location
	reqId1, err := conn.RenewCertificate(renewByCertificateDN)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("requested renewal for %s, will pickup by %s", pickupID, reqId1)

}

func TestReadPolicyConfiguration(t *testing.T) {
	//todo: add more zones
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	policy, err := conn.ReadPolicyConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	expectedPolice := endpoint.Policy{
		SubjectCNRegexes:         []string{"^.*$"},
		SubjectORegexes:          []string{"^.*$"},
		SubjectOURegexes:         []string{"^.*$"},
		SubjectSTRegexes:         []string{"^.*$"},
		SubjectLRegexes:          []string{"^.*$"},
		SubjectCRegexes:          []string{"^.*$"},
		AllowedKeyConfigurations: []endpoint.AllowedKeyConfiguration{{certificate.KeyTypeRSA, []int{2048, 4096}, nil}},
		DnsSanRegExs:             []string{"^.*$"},
		AllowWildcards:           true,
		AllowKeyReuse:            true,
	}

	if !reflect.DeepEqual(*policy, expectedPolice) {
		t.Fatalf("policy for zone %s is not as expected \nget:    %+v \nexpect: %+v", ctx.CloudZone, *policy, expectedPolice)
	}
}

func TestRetireCertificate(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = pickupID
	req.ChainOption = certificate.ChainOptionRootLast

	pcc, _ := certificate.NewPEMCollection(nil, nil, nil)
	startTime := time.Now()
	for {
		pcc, err = conn.RetrieveCertificate(req)
		if err != nil {
			_, ok := err.(endpoint.ErrCertificatePending)
			if ok {
				if time.Now().After(startTime.Add(time.Duration(600) * time.Second)) {
					err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupID}
					break
				}
				time.Sleep(time.Duration(10) * time.Second)
				continue
			}
			break
		}
		break
	}
	if err != nil {
		t.Fatalf("%s", err)
	}

	p, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	retireReq := &certificate.RetireRequest{}
	thumbprint := sha1.Sum(cert.Raw)
	hexThumbprint := hex.EncodeToString((thumbprint[:]))
	retireReq.Thumbprint = hexThumbprint

	// Letting VaaS some time to load certificate into inventory.
	// VaaS may be able to retrieve cert from API immediately, but storing in inventory may take a few seconds
	// or even stuck into it
	time.Sleep(time.Duration(2) * time.Second)
	err = conn.RetireCertificate(retireReq)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRetireCertificateWithPickUpID(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}

	retireReq := &certificate.RetireRequest{}
	retireReq.CertificateDN = pickupID

	// Letting VaaS some time to load certificate into inventory.
	// VaaS may be able to retrieve cert from API immediately, but storing in inventory may take a few seconds
	// or even stuck into it
	time.Sleep(time.Duration(2) * time.Second)
	err = conn.RetireCertificate(retireReq)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRetireCertificateTwice(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	err = conn.GenerateRequest(zoneConfig, req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	pickupID, err := conn.RequestCertificate(req)
	if err != nil {
		t.Fatalf("%s", err)
	}

	retireReq := &certificate.RetireRequest{}
	retireReq.CertificateDN = pickupID

	// Letting VaaS some time to load certificate into inventory.
	// VaaS may be able to retrieve cert from API immediately, but storing in inventory may take a few seconds
	// or even stuck into it
	time.Sleep(time.Duration(2) * time.Second)
	err = conn.RetireCertificate(retireReq)
	if err != nil {
		t.Fatalf("%s", err)
	}
	t.Log("Trying to retire the certificate a second time")
	retireReqSecond := &certificate.RetireRequest{}
	retireReqSecond.CertificateDN = pickupID

	err = conn.RetireCertificate(retireReqSecond)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestReadPolicyConfigurationOnlyEC(t *testing.T) {
	// IMPORTANT NOTE: Now in VCert, we are treating ED25519 Keys, as per it's a different algorithm from ECDSA, as another
	// type of key. This is conflicting with how VaaS handles EC Keys, as it considers ED25519 as another curve, which is
	// it shouldn't, this test may need to change in the future once this is solved
	//todo: add more zones
	conn := getTestConnector(ctx.VAASzoneEC)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	// This calls at the end of everything: policy.toPolicy() which is the function we wanted to test the KeyCurves
	policy, err := conn.ReadPolicyConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
	expectedPolice := endpoint.Policy{
		SubjectCNRegexes:         []string{".*\\.vfidev\\.com$"},
		SubjectORegexes:          []string{"^Venafi Inc.$"},
		SubjectOURegexes:         []string{"^Integrations$", "^Integration$"},
		SubjectSTRegexes:         []string{"^Utah$"},
		SubjectLRegexes:          []string{"^Salt Lake$"},
		SubjectCRegexes:          []string{"^US$"},
		AllowedKeyConfigurations: []endpoint.AllowedKeyConfiguration{{certificate.KeyTypeECDSA, nil, []certificate.EllipticCurve{certificate.EllipticCurveP256, certificate.EllipticCurveP384, certificate.EllipticCurveP521, certificate.EllipticCurveED25519}}},
		DnsSanRegExs:             []string{".*\\.vfidev\\.com$"},
		AllowWildcards:           false,
		AllowKeyReuse:            false,
	}

	if !reflect.DeepEqual(*policy, expectedPolice) {
		t.Fatalf("policy for zone %s is not as expected \nget:    %+v \nexpect: %+v", ctx.CloudZone, *policy, expectedPolice)
	}
}

func newSelfSignedCert() (string, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	serialNumber, _ := rand.Int(rand.Reader, big.NewInt(53298479))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: test.RandCN(),
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &rootKey.PublicKey, rootKey)
	if err != nil {
		return "", fmt.Errorf("can't generate fake cert")
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return string(b), nil
}

func TestImportCertificate(t *testing.T) {

	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	crt, err := newSelfSignedCert()
	if err != nil {
		t.Fatalf("%s", err)
	}
	importReq := &certificate.ImportRequest{
		PolicyDN:        "",
		ObjectName:      fmt.Sprintf("import%v.venafi.example.com", time.Now().Unix()),
		CertificateData: crt,
		PrivateKeyData:  "",
		Reconcile:       false,
	}

	importResp, err := conn.ImportCertificate(importReq)
	if err != nil {
		t.Fatalf("failed to import certificate: %s", err)
	}
	fmt.Printf("%+v\n", importResp)
}

func TestSetBaseURL(t *testing.T) {
	var err error
	condor := Connector{}
	url := "http://api2.projectc.venafi.com/v1"
	condor.baseURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(condor.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, condor.baseURL)
	}

	url = "http://api2.projectc.venafi.com/v1"
	condor.baseURL = ""
	condor.baseURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(condor.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, condor.baseURL)
	}

	url = "http://api2.projectc.venafi.com/v1/"
	condor.baseURL = ""
	condor.baseURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(condor.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, condor.baseURL)
	}

	url = "api2.projectc.venafi.com/v1/"
	condor.baseURL = ""
	condor.baseURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(condor.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, condor.baseURL)
	}
}

func TestGetURL(t *testing.T) {
	var err error
	condor := Connector{}
	url := "http://api2.projectc.venafi.com/v1/"
	condor.baseURL = ""
	condor.baseURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(condor.baseURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, condor.baseURL)
	}

	url = condor.getURL(urlResourceUserAccounts)
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", expectedURL, urlResourceUserAccounts)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", expectedURL, urlResourceUserAccounts), url)
	}

	url = condor.getURL(urlResourceCertificateRequests)
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRequests)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRequests), url)
	}

	url = condor.getURL(urlResourceCertificateRetrievePem)
	if !strings.EqualFold(url, fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRetrievePem)) {
		t.Fatalf("Get URL did not match expected value. Expected: %s Actual: %s", fmt.Sprintf("%s%s", expectedURL, urlResourceCertificateRetrievePem), url)
	}
	condor.baseURL = ""
	url = condor.getURL(urlResourceUserAccounts)
	if url == "" {
		t.Fatalf("Get URL did not return an error when the base url had not been set.")
	}
}

func TestRetrieveCertificatesList(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	for _, count := range []int{10, 100, 101, 153} {
		timeStarted := time.Now()
		l, err := conn.ListCertificates(endpoint.Filter{Limit: &count})
		if err != nil {
			t.Fatal(err)
		}
		set := make(map[string]struct{})
		for _, c := range l {
			set[c.Thumbprint] = struct{}{}
			if c.ValidTo.Before(timeStarted) {
				t.Errorf("cert %s is expired: %v", c.Thumbprint, c.ValidTo)
			}
		}
		if len(set) != count {
			t.Errorf("mismatched certificates number: wait %d, got %d (%d)", count, len(set), len(l))
		}
	}
}

func TestSearchCertificate(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatal(err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration()
	if err != nil {
		t.Fatal(err)
	}

	req := certificate.Request{}
	req.Subject.CommonName = test.RandCN()
	req.Timeout = time.Second * 10
	err = conn.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatal(err)
	}
	req.PickupID, err = conn.RequestCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := conn.RetrieveCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode([]byte(cert.Certificate))
	thumbprint := certThumbprint(p.Bytes)
	_, err = conn.searchCertificatesByFingerprint(thumbprint)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSetPolicy(t *testing.T) {
	appName := test.RandAppName()

	policyName := appName + "\\" + test.RandCitName()
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	localPolicy := test.GetCloudPolicySpecification()

	_, err = conn.SetPolicy(policyName, localPolicy)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//now update policy.
	t.Log("updating policy, modifying ps.Policy.Subject.OrgUnits = []string{\"DevOps\", \"QA\"}.")
	localPolicy.Policy.Subject.OrgUnits = []string{"DevOps", "QA"}
	//policyName = appName + "\\" + test.RandCitName()
	_, err = conn.SetPolicy(policyName, localPolicy)

	if err != nil {
		t.Fatalf("%s", err)
	}

	ps, err := conn.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//validate each attribute
	userDetails, err := getUserDetails(conn)
	//validating the default users attribute was created
	users := []string{
		//"jenkins@opensource.qa.venafi.io",
		userDetails.User.Username,
	}
	valid := test.IsArrayStringEqual(users, ps.Users)
	if !valid {
		t.Fatalf("It was expected that the current user %s be set as user of the PolicySpecification created but got %+q", users[0], ps.Users)
	}

	//Validating the addition of a user
	users = append(users, "resource-owner@opensource.qa.venafi.io")
	ps.Users = users

	_, err = conn.SetPolicy(policyName, ps)

	if err != nil {
		t.Fatalf("%s", err)
	}

	ps, err = conn.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	valid = test.IsArrayStringEqual(users, ps.Users)
	if !valid {
		t.Fatalf("The users are different, expected %+q but got %+q", users, ps.Users)
	}

	//validate subject attributes

	if ps == nil {
		t.Fatalf("specified Policy wasn't found")
	}

	if ps.Policy.Domains != nil && localPolicy.Policy.Domains != nil {
		valid := test.IsArrayStringEqual(localPolicy.Policy.Domains, ps.Policy.Domains)
		if !valid {
			t.Fatalf("specified domains are different, expected %+q but got %+q", localPolicy.Policy.Domains, ps.Policy.Domains)
		}
	}

	if *(ps.Policy.MaxValidDays) != *(localPolicy.Policy.MaxValidDays) {
		t.Fatalf("specified validity period is different")
	}

	//validate cert authority
	if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
		t.Fatalf("venafi policy doesn't have a certificate authority")
	}
	if *(ps.Policy.CertificateAuthority) != *(localPolicy.Policy.CertificateAuthority) {
		t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), *(localPolicy.Policy.CertificateAuthority))
	}

	if len(localPolicy.Policy.Subject.Orgs) > 0 {

		valid := test.IsArrayStringEqual(localPolicy.Policy.Subject.Orgs, ps.Policy.Subject.Orgs)
		if !valid {
			t.Fatalf("specified policy orgs are different, expected %+q but got %+q", localPolicy.Policy.Subject.Orgs, ps.Policy.Subject.Orgs)
		}

	}

	if len(localPolicy.Policy.Subject.OrgUnits) > 0 {

		valid := test.IsArrayStringEqual(localPolicy.Policy.Subject.OrgUnits, ps.Policy.Subject.OrgUnits)
		if !valid {
			t.Fatalf("specified policy orgs units are different, expected %+q but got %+q", localPolicy.Policy.Subject.OrgUnits, ps.Policy.Subject.OrgUnits)
		}

	}

	if len(localPolicy.Policy.Subject.Localities) > 0 {

		valid := test.IsArrayStringEqual(localPolicy.Policy.Subject.Localities, ps.Policy.Subject.Localities)
		if !valid {
			t.Fatalf("specified policy localities are different, expected %+q but got %+q", localPolicy.Policy.Subject.Localities, ps.Policy.Subject.Localities)
		}

	}

	if len(localPolicy.Policy.Subject.States) > 0 {

		valid := test.IsArrayStringEqual(localPolicy.Policy.Subject.States, ps.Policy.Subject.States)
		if !valid {
			t.Fatalf("specified policy states are different, expected %+q, but got %+q", localPolicy.Policy.Subject.States, ps.Policy.Subject.States)
		}

	}

	if len(localPolicy.Policy.Subject.Countries) > 0 {

		valid := test.IsArrayStringEqual(localPolicy.Policy.Subject.Countries, ps.Policy.Subject.Countries)
		if !valid {
			t.Fatalf("specified policy countries are different, expected %+q but got %+q", localPolicy.Policy.Subject.Countries, ps.Policy.Subject.Countries)
		}

	}

	//validate key pair values.

	if len(localPolicy.Policy.KeyPair.KeyTypes) > 0 {

		valid := test.IsArrayStringEqual(localPolicy.Policy.KeyPair.KeyTypes, ps.Policy.KeyPair.KeyTypes)
		if !valid {
			t.Fatalf("specified policy key types are different, expected %+q but got %+q", localPolicy.Policy.KeyPair.KeyTypes, ps.Policy.KeyPair.KeyTypes)
		}

	}

	if len(localPolicy.Policy.KeyPair.RsaKeySizes) > 0 {

		valid := test.IsArrayIntEqual(localPolicy.Policy.KeyPair.RsaKeySizes, ps.Policy.KeyPair.RsaKeySizes)
		if !valid {
			t.Fatalf("specified policy rsa key sizes are different, expected %+q but got %+q", localPolicy.Policy.KeyPair.RsaKeySizes, ps.Policy.KeyPair.RsaKeySizes)
		}

	}

	if localPolicy.Policy.KeyPair.ReuseAllowed != nil {

		if ps.Policy.KeyPair.ReuseAllowed == nil {
			t.Fatalf("specified policy rsa key sizes are not specified")
		}

		if *(ps.Policy.KeyPair.ReuseAllowed) != *(localPolicy.Policy.KeyPair.ReuseAllowed) {
			t.Fatalf("specified policy rsa key sizes are different")
		}

	}

	//validate default values.
	if localPolicy.Default.Subject.Org != nil {
		if ps.Default.Subject.Org == nil {
			t.Fatalf("specified policy default org is not specified")
		}
		if *(ps.Default.Subject.Org) != *(localPolicy.Default.Subject.Org) {
			t.Fatalf("specified policy default org is different")
		}
	}

	if len(localPolicy.Default.Subject.OrgUnits) > 0 {

		valid := test.IsArrayStringEqual(localPolicy.Default.Subject.OrgUnits, ps.Default.Subject.OrgUnits)

		if !valid {
			t.Fatalf("specified policy default org unit are different, expected %+q but got %+q", localPolicy.Default.Subject.OrgUnits, ps.Default.Subject.OrgUnits)
		}

	}

	if localPolicy.Default.Subject.Locality != nil {
		if ps.Default.Subject.Locality == nil {
			t.Fatalf("specified policy default locality is not specified")
		}
		if *(ps.Default.Subject.Locality) != *(localPolicy.Default.Subject.Locality) {
			t.Fatalf("specified policy default locality is different")
		}
	}

	if localPolicy.Default.Subject.State != nil {
		if ps.Default.Subject.State == nil {
			t.Fatalf("specified policy default state is not specified")
		}
		if *(ps.Default.Subject.State) != *(localPolicy.Default.Subject.State) {
			t.Fatalf("specified policy default state is different")
		}
	}

	if localPolicy.Default.Subject.Country != nil {
		if ps.Default.Subject.Country == nil {
			t.Fatalf("policy default country is not specified")
		}
		if *(ps.Default.Subject.Country) != *(localPolicy.Default.Subject.Country) {
			t.Fatalf("specified policy default country is different")
		}
	}

	if localPolicy.Default.KeyPair.KeyType != nil {
		if ps.Default.KeyPair.KeyType == nil {
			t.Fatalf("policy default key type is not specified ")
		}
		if *(ps.Default.KeyPair.KeyType) != *(localPolicy.Default.KeyPair.KeyType) {
			t.Fatalf("specified policy default key type is different")
		}
	}

	if localPolicy.Default.KeyPair.RsaKeySize != nil {
		if ps.Default.KeyPair.RsaKeySize == nil {
			t.Fatalf("policy default rsa key size is not specified")
		}
		if *(ps.Default.KeyPair.RsaKeySize) != *(localPolicy.Default.KeyPair.RsaKeySize) {
			t.Fatalf("specified policy default rsa key size is different")
		}
	}

	//validate SAN values.
	if *(localPolicy.Policy.SubjectAltNames.UriAllowed) != *(ps.Policy.SubjectAltNames.UriAllowed) {
		t.Fatalf("uriAllowed value is different, expected: %v but got %v",
			*(localPolicy.Policy.SubjectAltNames.UriAllowed),
			*(ps.Policy.SubjectAltNames.UriAllowed))
	}

	if *(localPolicy.Policy.SubjectAltNames.EmailAllowed) != *(ps.Policy.SubjectAltNames.EmailAllowed) {
		t.Fatalf("uriAllowed value is different, expected: %v but got %v",
			*(localPolicy.Policy.SubjectAltNames.EmailAllowed),
			*(ps.Policy.SubjectAltNames.EmailAllowed))
	}

	if *(localPolicy.Policy.SubjectAltNames.IpAllowed) != *(ps.Policy.SubjectAltNames.IpAllowed) {
		t.Fatalf("uriAllowed value is different, expected: %v but got %v",
			*(localPolicy.Policy.SubjectAltNames.IpAllowed),
			*(ps.Policy.SubjectAltNames.IpAllowed))
	}

	if len(localPolicy.Policy.SubjectAltNames.UriProtocols) > 0 {
		if len(ps.Policy.SubjectAltNames.UriProtocols) == 0 {
			t.Fatal("got 0 elements on uriProtocols ")
		}
		valid := test.IsArrayStringEqual(localPolicy.Policy.SubjectAltNames.UriProtocols, ps.Policy.SubjectAltNames.UriProtocols)
		if !valid {
			t.Fatalf("uri protocols are different, expected %+q but get %+q", localPolicy.Policy.SubjectAltNames.UriProtocols, ps.Policy.SubjectAltNames.UriProtocols)
		}
	}

	if len(localPolicy.Policy.SubjectAltNames.IpConstraints) > 0 {
		if len(ps.Policy.SubjectAltNames.IpConstraints) == 0 {
			t.Fatal("got 0 elements on ipConstrains ")
		}
		valid := test.IsArrayStringEqual(localPolicy.Policy.SubjectAltNames.IpConstraints, ps.Policy.SubjectAltNames.IpConstraints)
		if !valid {
			t.Fatalf("ip constrains are different, expected %+q but get %+q", localPolicy.Policy.SubjectAltNames.IpConstraints, ps.Policy.SubjectAltNames.IpConstraints)
		}
	}

}

func TestGetPolicy(t *testing.T) {

	t.Skip() //this is just for development purpose

	policyName := os.Getenv("CLOUD_POLICY_MANAGEMENT_SAMPLE")
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specifiedPS := test.GetCloudPolicySpecification()

	ps, err := conn.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//validate each attribute
	//validate subject attributes

	if ps == nil {
		t.Fatalf("specified Policy wasn't found")
	}

	if ps.Policy.Domains != nil && specifiedPS.Policy.Domains != nil {
		domains := policy.ConvertToRegex(specifiedPS.Policy.Domains, policy.IsWildcardAllowed(*(specifiedPS)))
		valid := test.IsArrayStringEqual(domains, ps.Policy.Domains)
		if !valid {
			t.Fatalf("specified domains are different")
		}
	}

	if *(ps.Policy.MaxValidDays) != *(specifiedPS.Policy.MaxValidDays) {
		t.Fatalf("specified validity period is different")
	}

	//validate cert authority
	if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
		t.Fatalf("venafi policy doesn't have a certificate authority")
	}
	if *(ps.Policy.CertificateAuthority) != *(specifiedPS.Policy.CertificateAuthority) {
		t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), *(specifiedPS.Policy.CertificateAuthority))
	}

	if specifiedPS.Policy.Subject.Orgs != nil {

		if ps.Policy.Subject.Orgs == nil {
			t.Fatalf("specified policy orgs are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Orgs, ps.Policy.Subject.Orgs)
		if !valid {
			t.Fatalf("specified policy orgs are different")
		}

	}

	if specifiedPS.Policy.Subject.OrgUnits != nil {

		if ps.Policy.Subject.OrgUnits == nil {
			t.Fatalf("specified policy orgs units are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.OrgUnits, ps.Policy.Subject.OrgUnits)
		if !valid {
			t.Fatalf("specified policy orgs units are different")
		}

	}

	if specifiedPS.Policy.Subject.Localities != nil {

		if ps.Policy.Subject.Localities == nil {
			t.Fatalf("specified policy localities are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Localities, ps.Policy.Subject.Localities)
		if !valid {
			t.Fatalf("specified policy localities are different")
		}

	}

	if specifiedPS.Policy.Subject.States != nil {

		if ps.Policy.Subject.States == nil {
			t.Fatalf("specified policy states are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.States, ps.Policy.Subject.States)
		if !valid {
			t.Fatalf("specified policy states are different")
		}

	}

	if specifiedPS.Policy.Subject.Countries != nil {

		if ps.Policy.Subject.Countries == nil {
			t.Fatalf("specified policy countries are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Countries, ps.Policy.Subject.Countries)
		if !valid {
			t.Fatalf("specified policy countries are different")
		}

	}

	//validate key pair values.

	if specifiedPS.Policy.KeyPair.KeyTypes != nil {

		if ps.Policy.KeyPair.KeyTypes == nil {
			t.Fatalf("specified policy key types are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.KeyPair.KeyTypes, ps.Policy.KeyPair.KeyTypes)
		if !valid {
			t.Fatalf("specified policy key types are different")
		}

	}

	if specifiedPS.Policy.KeyPair.RsaKeySizes != nil {

		if ps.Policy.KeyPair.RsaKeySizes == nil {
			t.Fatalf("specified policy rsa key sizes are not specified")
		}

		valid := test.IsArrayIntEqual(specifiedPS.Policy.KeyPair.RsaKeySizes, ps.Policy.KeyPair.RsaKeySizes)
		if !valid {
			t.Fatalf("specified policy rsa key sizes are different")
		}

	}

	if specifiedPS.Policy.KeyPair.ReuseAllowed != nil {

		if ps.Policy.KeyPair.ReuseAllowed == nil {
			t.Fatalf("specified policy rsa key sizes are not specified")
		}

		if *(ps.Policy.KeyPair.ReuseAllowed) != *(specifiedPS.Policy.KeyPair.ReuseAllowed) {
			t.Fatalf("specified policy rsa key sizes are different")
		}

	}

	//validate default values.
	if specifiedPS.Default.Subject.Org != nil {
		if ps.Default.Subject.Org == nil {
			t.Fatalf("specified policy default org is not specified")
		}
		if *(ps.Default.Subject.Org) != *(specifiedPS.Default.Subject.Org) {
			t.Fatalf("specified policy default org is different")
		}
	}

	if specifiedPS.Default.Subject.OrgUnits != nil {

		if ps.Default.Subject.OrgUnits == nil {
			t.Fatalf("specified policy default org is not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Default.Subject.OrgUnits, ps.Default.Subject.OrgUnits)

		if !valid {
			t.Fatalf("specified policy default org unit are different")
		}

	}

	if specifiedPS.Default.Subject.Locality != nil {
		if ps.Default.Subject.Locality == nil {
			t.Fatalf("specified policy default locality is not specified")
		}
		if *(ps.Default.Subject.Locality) != *(specifiedPS.Default.Subject.Locality) {
			t.Fatalf("specified policy default locality is different")
		}
	}

	if specifiedPS.Default.Subject.State != nil {
		if ps.Default.Subject.State == nil {
			t.Fatalf("specified policy default state is not specified")
		}
		if *(ps.Default.Subject.State) != *(specifiedPS.Default.Subject.State) {
			t.Fatalf("specified policy default state is different")
		}
	}

	if specifiedPS.Default.Subject.Country != nil {
		if ps.Default.Subject.Country == nil {
			t.Fatalf("policy default country is not specified")
		}
		if *(ps.Default.Subject.Country) != *(specifiedPS.Default.Subject.Country) {
			t.Fatalf("specified policy default country is different")
		}
	}

	if specifiedPS.Default.KeyPair.KeyType != nil {
		if ps.Default.KeyPair.KeyType == nil {
			t.Fatalf("policy default key type is not specified ")
		}
		if *(ps.Default.KeyPair.KeyType) != *(specifiedPS.Default.KeyPair.KeyType) {
			t.Fatalf("specified policy default key type is different")
		}
	}

	if specifiedPS.Default.KeyPair.RsaKeySize != nil {
		if ps.Default.KeyPair.RsaKeySize == nil {
			t.Fatalf("policy default rsa key size is not specified")
		}
		if *(ps.Default.KeyPair.RsaKeySize) != *(specifiedPS.Default.KeyPair.RsaKeySize) {
			t.Fatalf("specified policy default rsa key size is different")
		}
	}

}

func TestGetPolicyOnlyEC(t *testing.T) {

	// This test covers GetPolicy function from connector to test EC curves are return correctly for all the values,
	// including RecommendSettings

	policyName := os.Getenv("VAAS_ZONE_EC")
	conn := getTestConnector(ctx.VAASzoneEC)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specifiedPS := test.GetVAASpolicySpecificationEC()

	ps, err := conn.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//validate each attribute
	//validate subject attributes

	if ps == nil {
		t.Fatalf("specified Policy wasn't found")
	}

	if ps.Policy.Domains != nil && specifiedPS.Policy.Domains != nil {
		valid := test.IsArrayStringEqual(specifiedPS.Policy.Domains, ps.Policy.Domains)
		if !valid {
			t.Fatalf("specified domains are different")
		}
	}

	if *(ps.Policy.MaxValidDays) != *(specifiedPS.Policy.MaxValidDays) {
		t.Fatalf("specified validity period is different")
	}

	//validate cert authority
	if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
		t.Fatalf("venafi policy doesn't have a certificate authority")
	}
	if *(ps.Policy.CertificateAuthority) != *(specifiedPS.Policy.CertificateAuthority) {
		t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), *(specifiedPS.Policy.CertificateAuthority))
	}

	if specifiedPS.Policy.Subject.Orgs != nil {

		if ps.Policy.Subject.Orgs == nil {
			t.Fatalf("specified policy orgs are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Orgs, ps.Policy.Subject.Orgs)
		if !valid {
			t.Fatalf("specified policy orgs are different")
		}

	}

	if specifiedPS.Policy.Subject.OrgUnits != nil {

		if ps.Policy.Subject.OrgUnits == nil {
			t.Fatalf("specified policy orgs units are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.OrgUnits, ps.Policy.Subject.OrgUnits)
		if !valid {
			t.Fatalf("specified policy orgs units are different")
		}

	}

	if specifiedPS.Policy.Subject.Localities != nil {

		if ps.Policy.Subject.Localities == nil {
			t.Fatalf("specified policy localities are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Localities, ps.Policy.Subject.Localities)
		if !valid {
			t.Fatalf("specified policy localities are different")
		}

	}

	if specifiedPS.Policy.Subject.States != nil {

		if ps.Policy.Subject.States == nil {
			t.Fatalf("specified policy states are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.States, ps.Policy.Subject.States)
		if !valid {
			t.Fatalf("specified policy states are different")
		}

	}

	if specifiedPS.Policy.Subject.Countries != nil {

		if ps.Policy.Subject.Countries == nil {
			t.Fatalf("specified policy countries are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.Subject.Countries, ps.Policy.Subject.Countries)
		if !valid {
			t.Fatalf("specified policy countries are different")
		}

	}

	//validate key pair values.

	if specifiedPS.Policy.KeyPair.KeyTypes != nil {

		if ps.Policy.KeyPair.KeyTypes == nil {
			t.Fatalf("specified policy key types are not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Policy.KeyPair.KeyTypes, ps.Policy.KeyPair.KeyTypes)
		if !valid {
			t.Fatalf("specified policy key types are different")
		}

	}

	if specifiedPS.Policy.KeyPair.RsaKeySizes != nil {

		if ps.Policy.KeyPair.RsaKeySizes == nil {
			t.Fatalf("specified policy rsa key sizes are not specified")
		}

		valid := test.IsArrayIntEqual(specifiedPS.Policy.KeyPair.RsaKeySizes, ps.Policy.KeyPair.RsaKeySizes)
		if !valid {
			t.Fatalf("specified policy rsa key sizes are different")
		}

	}

	if specifiedPS.Policy.KeyPair.ReuseAllowed != nil {

		if ps.Policy.KeyPair.ReuseAllowed == nil {
			t.Fatalf("specified policy rsa key sizes are not specified")
		}

		if *(ps.Policy.KeyPair.ReuseAllowed) != *(specifiedPS.Policy.KeyPair.ReuseAllowed) {
			t.Fatalf("specified policy rsa key sizes are different")
		}

	}

	//validate default values.
	if specifiedPS.Default.Subject.Org != nil {
		if ps.Default.Subject.Org == nil {
			t.Fatalf("specified policy default org is not specified")
		}
		if *(ps.Default.Subject.Org) != *(specifiedPS.Default.Subject.Org) {
			t.Fatalf("specified policy default org is different")
		}
	}

	if specifiedPS.Default.Subject.OrgUnits != nil {

		if ps.Default.Subject.OrgUnits == nil {
			t.Fatalf("specified policy default org is not specified")
		}

		valid := test.IsArrayStringEqual(specifiedPS.Default.Subject.OrgUnits, ps.Default.Subject.OrgUnits)

		if !valid {
			t.Fatalf("specified policy default org unit are different")
		}

	}

	if specifiedPS.Default.Subject.Locality != nil {
		if ps.Default.Subject.Locality == nil {
			t.Fatalf("specified policy default locality is not specified")
		}
		if *(ps.Default.Subject.Locality) != *(specifiedPS.Default.Subject.Locality) {
			t.Fatalf("specified policy default locality is different")
		}
	}

	if specifiedPS.Default.Subject.State != nil {
		if ps.Default.Subject.State == nil {
			t.Fatalf("specified policy default state is not specified")
		}
		if *(ps.Default.Subject.State) != *(specifiedPS.Default.Subject.State) {
			t.Fatalf("specified policy default state is different")
		}
	}

	if specifiedPS.Default.Subject.Country != nil {
		if ps.Default.Subject.Country == nil {
			t.Fatalf("policy default country is not specified")
		}
		if *(ps.Default.Subject.Country) != *(specifiedPS.Default.Subject.Country) {
			t.Fatalf("specified policy default country is different")
		}
	}

	if specifiedPS.Default.KeyPair.KeyType != nil {
		if ps.Default.KeyPair.KeyType == nil {
			t.Fatalf("policy default key type is not specified ")
		}
		psDefaultKeyType := ps.Default.KeyPair.KeyType
		psDefaultKeyTypeConverted := test.UnifyECvalue(*psDefaultKeyType)
		ps.Default.KeyPair.KeyType = &psDefaultKeyTypeConverted
		if *(ps.Default.KeyPair.KeyType) != *(specifiedPS.Default.KeyPair.KeyType) {

			t.Fatalf("specified policy default key type is different")
		}
	}

	if specifiedPS.Default.KeyPair.RsaKeySize != nil {
		if ps.Default.KeyPair.RsaKeySize == nil {
			t.Fatalf("policy default rsa key size is not specified")
		}
		if *(ps.Default.KeyPair.RsaKeySize) != *(specifiedPS.Default.KeyPair.RsaKeySize) {
			t.Fatalf("specified policy default rsa key size is different")
		}
	}

}

func TestSetEmptyPolicy(t *testing.T) {

	policyName := test.RandAppName() + "\\" + test.RandCitName()
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specification := policy.PolicySpecification{}

	_, err = conn.SetPolicy(policyName, &specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

}

func TestSetDefaultPolicyValuesAndValidate(t *testing.T) {

	policyName := test.RandAppName() + "\\" + test.RandCitName()
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specification := test.GetCloudPolicySpecification()

	specification.Policy = nil
	ec := "P384"
	serGenerated := true
	specification.Default.KeyPair.EllipticCurve = &ec
	specification.Default.KeyPair.ServiceGenerated = &serGenerated
	ctx.CloudZone = policyName

	_, err = conn.SetPolicy(policyName, specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//get the created policy
	ps, err := conn.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if ps.Default == nil {
		t.Fatalf("policy's defaults are nil")
	}
	localDefault := specification.Default
	remoteDefault := ps.Default

	if remoteDefault.Subject == nil {
		t.Fatalf("policy's default subject is nil")
	}
	if *(remoteDefault.Subject.Locality) != *(localDefault.Subject.Locality) {
		t.Fatalf("policy's default locality is different expected: %s but get %s", *(localDefault.Subject.Locality), *(remoteDefault.Subject.Locality))
	}

	if *(remoteDefault.Subject.Country) != *(localDefault.Subject.Country) {
		t.Fatalf("policy's default country is different expected: %s but get %s", *(localDefault.Subject.Country), *(remoteDefault.Subject.Country))
	}

	if *(remoteDefault.Subject.State) != *(localDefault.Subject.State) {
		t.Fatalf("policy's default state is different expected: %s but get %s", *(localDefault.Subject.State), *(remoteDefault.Subject.State))
	}

	if *(remoteDefault.Subject.Org) != *(localDefault.Subject.Org) {
		t.Fatalf("policy's default org is different expected: %s but get %s", *(localDefault.Subject.Org), *(remoteDefault.Subject.Org))
	}

	valid := test.IsArrayStringEqual(remoteDefault.Subject.OrgUnits, localDefault.Subject.OrgUnits)
	if !valid {
		t.Fatalf("policy's default orgUnits are different")
	}

	if remoteDefault.KeyPair == nil {
		t.Fatalf("policy's default keyPair is nil")
	}

	if *(remoteDefault.KeyPair.KeyType) != *(localDefault.KeyPair.KeyType) {
		t.Fatalf("policy's default keyType is different expected: %s but get %s", *(localDefault.KeyPair.KeyType), *(remoteDefault.KeyPair.KeyType))
	}

	if *(remoteDefault.KeyPair.RsaKeySize) != *(localDefault.KeyPair.RsaKeySize) {
		t.Fatalf("policy's default RsaKeySize is different expected: %s but get %s", strconv.Itoa(*(localDefault.KeyPair.RsaKeySize)), strconv.Itoa(*(remoteDefault.KeyPair.RsaKeySize)))
	}

}

func TestSetPolicyValuesAndValidate(t *testing.T) {

	policyName := test.RandAppName() + "\\" + test.RandCitName()
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specification := test.GetCloudPolicySpecification()

	specification.Default = nil
	ctx.CloudZone = policyName

	_, err = conn.SetPolicy(policyName, specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//get the created policy
	ps, err := conn.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if ps.Policy == nil {
		t.Fatalf("policy is nil")
	}
	localPolicy := specification.Policy
	remotePolicy := ps.Policy

	if remotePolicy.Subject == nil {
		t.Fatalf("policy's subject is nil")
	}

	valid := test.IsArrayStringEqual(remotePolicy.Subject.Localities, localPolicy.Subject.Localities)
	if !valid {
		t.Fatalf("policy's localities are different expected: %+q but get  %+q ", localPolicy.Subject.Localities, remotePolicy.Subject.Localities)
	}

	valid = test.IsArrayStringEqual(remotePolicy.Subject.Countries, localPolicy.Subject.Countries)
	if !valid {
		t.Fatalf("policy's countries are different expected: %+q but get  %+q", localPolicy.Subject.Countries, remotePolicy.Subject.Countries)
	}

	valid = test.IsArrayStringEqual(remotePolicy.Subject.States, localPolicy.Subject.States)
	if !valid {
		t.Fatalf("policy's states are different expected: %+q but get  %+q", localPolicy.Subject.States, remotePolicy.Subject.States)
	}

	valid = test.IsArrayStringEqual(remotePolicy.Subject.Orgs, localPolicy.Subject.Orgs)
	if !valid {
		t.Fatalf("policy's default org are different expected: %+q but get  %+q", localPolicy.Subject.Orgs, remotePolicy.Subject.Orgs)
	}

	valid = test.IsArrayStringEqual(remotePolicy.Subject.OrgUnits, localPolicy.Subject.OrgUnits)
	if !valid {
		t.Fatalf("policy's org units are different expected: %+q but get  %+q", localPolicy.Subject.OrgUnits, remotePolicy.Subject.OrgUnits)
	}

	if remotePolicy.KeyPair == nil {
		t.Fatalf("policy's keyPair is nil")
	}

	valid = test.IsArrayStringEqual(remotePolicy.KeyPair.KeyTypes, localPolicy.KeyPair.KeyTypes)
	if !valid {
		t.Fatalf("policy's keyTypes are different expected: %+q but get  %+q", localPolicy.KeyPair.KeyTypes, remotePolicy.KeyPair.KeyTypes)
	}

	valid = test.IsArrayIntEqual(remotePolicy.KeyPair.RsaKeySizes, localPolicy.KeyPair.RsaKeySizes)
	if !valid {
		t.Fatalf("policy's RsaKeySizes are different expected:  %+q but get  %+q", localPolicy.KeyPair.RsaKeySizes, remotePolicy.KeyPair.RsaKeySizes)
	}

}

// This test is just for verifying that a policy can be created using ENTRUST CA.
func TestSetPolicyEntrust(t *testing.T) {

	policyName := test.RandAppName() + "\\" + test.RandCitName()
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specification := test.GetCloudPolicySpecification()
	//change default CA to Entrust
	caName := os.Getenv("CLOUD_ENTRUST_CA_NAME")
	specification.Policy.CertificateAuthority = &caName

	_, err = conn.SetPolicy(policyName, specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

	ps, err := conn.GetPolicy(policyName)

	if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
		t.Fatalf("venafi policy doesn't have a certificate authority")
	}
	if *(ps.Policy.CertificateAuthority) != *(specification.Policy.CertificateAuthority) {
		t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), *(specification.Policy.CertificateAuthority))
	}

}

/*
*
This test is just for verifying that a policy can be created using DIGICERT	 CA.
*/
func TestSetPolicyDigicert(t *testing.T) {

	policyName := test.RandAppName() + "\\" + test.RandCitName()
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specification := test.GetCloudPolicySpecification()

	//change default CA to Digiert
	caName := os.Getenv("CLOUD_DIGICERT_CA_NAME")
	specification.Policy.CertificateAuthority = &caName
	_, err = conn.SetPolicy(policyName, specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

	ps, err := conn.GetPolicy(policyName)

	if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
		t.Fatalf("venafi policy doesn't have a certificate authority")
	}
	if *(ps.Policy.CertificateAuthority) != *(specification.Policy.CertificateAuthority) {
		t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), *(specification.Policy.CertificateAuthority))
	}
}

func TestCreateCertServiceCSR(t *testing.T) {
	policyName := os.Getenv("CLOUD_ZONE_RESTRICTED")
	conn := getTestConnector(policyName)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := getBasicRequest()
	req.DNSNames = []string{req.Subject.CommonName}

	req.CsrOrigin = certificate.ServiceGeneratedCSR

	id, err := conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = id
	req.ChainOption = certificate.ChainOptionRootFirst
	req.KeyPassword = "abcede"
	req.Timeout = time.Duration(180) * time.Second
	pcc, err := conn.RetrieveCertificate(&req)

	if pcc.Certificate == "" {
		t.Fatalf("certificate with pickup id: %s is empty", req.PickupID)
	}
	if pcc.PrivateKey == "" {
		t.Fatalf("private key for certificate with pickup id: %s is empty", req.PickupID)
	}
	if len(pcc.Chain) == 0 {
		t.Fatalf("chai for certificate with pickup id: %s is empty", req.PickupID)
	}

}

func TestCreateCertServiceCSRWithDefaults(t *testing.T) {
	t.Skip("it will enabled on the future")
	conn := getTestConnector("App Alfa\\Amoo")
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := certificate.Request{}
	req.Subject.CommonName = test.RandCN()

	req.CsrOrigin = certificate.ServiceGeneratedCSR

	id, err := conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = id
	req.ChainOption = certificate.ChainOptionRootFirst
	req.KeyPassword = "abcede"
	req.Timeout = time.Duration(180) * time.Second
	pcc, err := conn.RetrieveCertificate(&req)

	if pcc.Certificate == "" {
		t.Fatalf("certificate with pickup id: %s is empty", req.PickupID)
	}
	if pcc.PrivateKey == "" {
		t.Fatalf("private key for certificate with pickup id: %s is empty", req.PickupID)
	}
	if len(pcc.Chain) == 0 {
		t.Fatalf("chai for certificate with pickup id: %s is empty", req.PickupID)
	}

}

func TestGetDefaultCsrAttributes(t *testing.T) {

	policyName := os.Getenv("CLOUD_ZONE_RESTRICTED")
	conn := getTestConnector(policyName)
	conn.verbose = true
	request := &certificate.Request{}
	request.Subject.CommonName = "test.vfidev.com"

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}
	attributes, err := getCsrAttributes(conn, request)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if attributes == nil {
		t.Fatal("attributes are nil")
	}
}

func TestGetCsrAttributes(t *testing.T) {

	policyName := os.Getenv("CLOUD_ZONE_RESTRICTED")
	conn := getTestConnector(policyName)
	conn.verbose = true
	req := getBasicRequest()
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}
	attributes, err := getCsrAttributes(conn, &req)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if attributes == nil {
		t.Fatal("attributes are nil")
	}
}

func TestCertificateSanTypes(t *testing.T) {

	ip := net.ParseIP("127.0.0.1")
	policyName := os.Getenv("CLOUD_ZONE_RESTRICTED")
	conn := getTestConnector(policyName)
	conn.verbose = true
	req := getBasicRequest()

	//email sans
	req.EmailAddresses = []string{fmt.Sprint("test@", req.Subject.CommonName)}

	//ip sans˘
	req.IPAddresses = []net.IP{ip}

	//uri sans
	uri, _ := url.Parse(fmt.Sprint("https://", req.Subject.CommonName))
	req.URIs = []*url.URL{uri}

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}
	attributes, err := getCsrAttributes(conn, &req)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if attributes == nil {
		t.Fatal("attributes are nil")
	}
}

func TestVerifyCSRServiceGenerated(t *testing.T) {
	policyName := os.Getenv("CLOUD_ZONE_RESTRICTED")

	conn := getTestConnector(policyName)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := getBasicRequest()

	req.CsrOrigin = certificate.ServiceGeneratedCSR

	id, err := conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = id
	req.ChainOption = certificate.ChainOptionRootFirst
	req.KeyPassword = "abcede"
	req.Timeout = time.Duration(180) * time.Second

	isCSRService, err := conn.IsCSRServiceGenerated(&req)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if !isCSRService {
		t.Fatal("Requested certificate should be CSR service generated")
	}

}

func TestGenerateCertificateEC(t *testing.T) {
	policyName := os.Getenv("VAAS_ZONE_ONLY_EC")

	conn := getTestConnector(policyName)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := getBasicRequest()
	req.KeyType = certificate.KeyTypeECDSA
	req.KeyCurve = certificate.EllipticCurveP384
	req.CsrOrigin = certificate.ServiceGeneratedCSR

	id, err := conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = id
	req.ChainOption = certificate.ChainOptionRootFirst
	req.KeyPassword = "abcede"
	req.Timeout = time.Duration(180) * time.Second

	isCSRService, err := conn.IsCSRServiceGenerated(&req)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if !isCSRService {
		t.Fatal("Requested certificate should be CSR service generated")
	}

}

func TestGenerateCertificateECDefault(t *testing.T) {
	policyName := os.Getenv("VAAS_ZONE_ONLY_EC")

	conn := getTestConnector(policyName)
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	if err != nil {
		t.Fatalf("%s", err)
	}
	req := getBasicRequest()
	req.KeyType = certificate.KeyTypeECDSA
	req.CsrOrigin = certificate.ServiceGeneratedCSR

	id, err := conn.RequestCertificate(&req)
	if err != nil {
		t.Fatalf("%s", err)
	}
	req.PickupID = id
	req.ChainOption = certificate.ChainOptionRootFirst
	req.KeyPassword = "abcede"
	req.Timeout = time.Duration(180) * time.Second

	isCSRService, err := conn.IsCSRServiceGenerated(&req)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if !isCSRService {
		t.Fatal("Requested certificate should be CSR service generated")
	}

}

func TestGetType(t *testing.T) {
	policyName := os.Getenv("CLOUD_ZONE_RESTRICTED")

	conn := getTestConnector(policyName)

	if endpoint.ConnectorTypeCloud != conn.GetType() {
		t.Fatalf("expected: %s but get %s", endpoint.ConnectorTypeCloud.String(), conn.GetType().String())
	}

}

func getBasicRequest() certificate.Request {

	req := certificate.Request{}
	req.Subject.CommonName = test.RandSpecificCN("test.vfidev.com")
	req.Subject.Organization = []string{"Venafi Inc."}
	req.Subject.OrganizationalUnit = []string{"Integrations"}
	req.Subject.Locality = []string{"Salt Lake"}
	req.Subject.Province = []string{"Utah"}
	req.Subject.Country = []string{"US"}
	req.DNSNames = []string{req.Subject.CommonName}

	return req
}

// TODO: Expand unit tests to cover more cases
func TestSearchValidCertificate(t *testing.T) {
	conn := getTestConnector(ctx.CloudZone)
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatal(err)
	}

	cn := "one.example.com"
	// There are 2 certificates here
	sans := &certificate.Sans{DNS: []string{cn, "two.example.com"}}
	// and 2 more, certificates here
	// sans := &certificate.Sans{DNS: []string{cn, "two.example.com", "three.example.com"}}

	// TODO: Filter zone
	// with this zone you should be able to find those certificates
	zone := "Open Source Integrations\\Unrestricted"
	// but not with this (or any non valid zone)
	// zone := "Invalid zone\\The CIT"

	// use time.Duration instead of integer
	day := 24 * time.Hour
	certMinTimeLeft := 3 * day

	certificate, err := conn.SearchCertificate(zone, cn, sans, certMinTimeLeft)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if certificate == nil {
		t.Fatal("Should have found a certificate")
	}

	fmt.Printf("%v\n", util.GetJsonAsString(*certificate))
}
