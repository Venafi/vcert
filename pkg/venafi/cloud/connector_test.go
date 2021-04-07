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
	"github.com/Venafi/vcert/v4/pkg/policy"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"github.com/Venafi/vcert/v4/test"
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

func TestRequestCertificateWithValidDays(t *testing.T) {
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

	validHours := 144
	req.ValidityHours = validHours
	req.IssuerHint = "MICROSOFT"

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
	utcNow := time.Now().In(loc)
	expectedValidDate := utcNow.AddDate(0, 0, validHours/24).Format("2006-01-02")

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
		SubjectCNRegexes:         []string{"^.*.example.com$", "^.*.example.org$", "^.*.example.net$", "^.*.invalid$", "^.*.local$", "^.*.localhost$", "^.*.test$", "^.*.vfidev.com$"},
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

func TestSetZone(t *testing.T) {

	policyName := test.RandAppName() + "\\" + test.RandCitName()
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	ps := test.GetCloudPolicySpecification()

	_, err = conn.SetPolicy(policyName, ps)

	if err != nil {
		t.Fatalf("%s", err)
	}

}

func TestGetPolicy(t *testing.T) {

	policyName := os.Getenv("CLOUD_POLICY_MANAGEMENT_SAMPLE")
	conn := getTestConnector(ctx.CloudZone)
	conn.verbose = true

	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})

	if err != nil {
		t.Fatalf("%s", err)
	}

	specifiedPS := test.GetCloudPolicySpecification()

	ps, err := conn.GetPolicySpecification(policyName)

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

	//validate cert authority id.
	certAuth, err := getCertificateAuthorityAccountId(*(specifiedPS.Policy.CertificateAuthority), conn)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if certAuth != "" {
		if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
			t.Fatalf("venafi policy doesn't have a certificate authority")
		}
		if *(ps.Policy.CertificateAuthority) != certAuth {
			t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), certAuth)
		}
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
