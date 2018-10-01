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
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/test"
	"os"
	"strings"
	"testing"
	"time"
)

var ctx *test.Context

func init() {
	ctx = test.GetContext()
	// http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if ctx.CloudAPIkey == "" {
		fmt.Println("API key cannot be empty. See Makefile")
		os.Exit(1)
	}
}

func getTestConnector() *Connector {
	c := NewConnector(true, nil)
	c.SetBaseURL(ctx.CloudUrl)
	return c
}

func TestPing(t *testing.T) {
	conn := getTestConnector()
	err := conn.Ping()
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestAuthenticate(t *testing.T) {
	conn := getTestConnector()
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestReadZoneConfiguration(t *testing.T) {
	conn := getTestConnector()
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = conn.ReadZoneConfiguration(ctx.CloudZone)
	if err != nil {
		t.Fatalf("%s", err)
	}
	_, err = conn.ReadZoneConfiguration("blob")
	if err == nil {
		t.Fatalf("Unknown zone should have resulted in an error")
	}
}

func TestRequestCertificate(t *testing.T) {
	conn := getTestConnector()
	conn.verbose = true
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration(ctx.CloudZone)
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
	_, err = conn.RequestCertificate(&req, ctx.CloudZone)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRetrieveCertificate(t *testing.T) {
	conn := getTestConnector()
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration(ctx.CloudZone)
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
	pickupID, err := conn.RequestCertificate(req, ctx.CloudZone)
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
	conn := getTestConnector()
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration(ctx.CloudZone)
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
	pickupID, err := conn.RequestCertificate(req, ctx.CloudZone)
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
	conn := getTestConnector()
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration(ctx.CloudZone)
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
	reqId, err := conn.RequestCertificate(req, ctx.CloudZone)
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
	conn := getTestConnector()
	err := conn.Authenticate(&endpoint.Authentication{APIKey: ctx.CloudAPIkey})
	if err != nil {
		t.Fatalf("%s", err)
	}
	zoneConfig, err := conn.ReadZoneConfiguration(ctx.CloudZone)
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
	pickupID, err := conn.RequestCertificate(req, ctx.CloudZone)
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
