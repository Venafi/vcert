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

package tpp

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/test"
	"net/http"
	"os"
	"testing"
	"time"
)

var ctx *test.Context

func init() {
	ctx = test.GetContext()
	ctx = test.GetEnvContext()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if ctx.TPPurl == "" {
		fmt.Println("TPP URL cannot be empty. See Makefile")
		os.Exit(1)
	}
}

func getTestConnector() *Connector {
	return NewConnector(false, nil)
}

func TestPingTPP(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
	}
	err = tpp.Ping()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
}

func TestBadPingTPP(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL("http://bonjo-w10dev:333/vedsdk/")
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: http://bonjo-w10dev:333/vedsdk/", err)
	}
	err = tpp.Ping()
	if err == nil {
		t.Fatalf("err should not be nil, URL does not exist")
	}
}

func TestAuthorizeToTPP(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
	}
	auth := &endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword}
	err = tpp.Authenticate(auth)
	if err != nil {
		t.Fatalf("err is not nil, err: %s, %+v", err, auth)
	}
}

func TestBadAuthorizeToTPP(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
	}
	err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: "wrongPassword"})
	if err == nil {
		t.Fatalf("err should not be nil, bad password was used")
	}
}

func TestReadConfigData(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	_, err = tpp.ReadZoneConfiguration(getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
}

func TestBadReadConfigData(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	_, err = tpp.ReadZoneConfiguration(getPolicyDN("Wrong Policy"))
	if err == nil {
		t.Fatalf("err should not be nil, invalid policy was used")
	}
}

func TestRequestCertificate(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration(getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	cn := test.RandCN()
	req := &certificate.Request{}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	req.FriendlyName = cn
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	t.Logf("getPolicyDN(ctx.TPPZone) = %s", getPolicyDN(ctx.TPPZone))
	_, err = tpp.RequestCertificate(req, getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
}

func TestRequestCertificateServiceGenerated(t *testing.T) {
	tpp := getTestConnector()
	tpp.SetBaseURL(ctx.TPPurl)
	tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
	config, err := tpp.ReadZoneConfiguration(getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatal("failed to read zone configuration")
	}

	cn := test.RandCN()
	req := &certificate.Request{}
	req.Subject.CommonName = cn

	req.KeyLength = 2048
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	req.FriendlyName = cn

	req.CsrOrigin = certificate.ServiceGeneratedCSR
	req.FetchPrivateKey = true
	req.KeyPassword = "newPassw0rd!"

	config.UpdateCertificateRequest(req)

	pickupId, err := tpp.RequestCertificate(req, getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	req.PickupID = pickupId
	req.ChainOption = certificate.ChainOptionIgnore

	t.Log(pickupId)

	var isPending = true
	var pcc *certificate.PEMCollection
	for isPending {
		t.Logf("%s is pending...", pickupId)
		time.Sleep(time.Second * 1)
		pcc, err = tpp.RetrieveCertificate(req)
		_, isPending = err.(endpoint.ErrCertificatePending)
	}
	if err != nil {
		t.Fatalf("%s, request was %+v", err, req)
	}
	if pcc.PrivateKey == "" {
		t.Fatalf("Private key was not returned by endpoint")
	}
	t.Logf("%+v", pcc)
}

func TestRetrieveNonIssuedCertificate(t *testing.T) {
	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration(getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req := &certificate.Request{}
	req.Subject.CommonName = "vcert.test.vfidev.com"
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	req.FriendlyName = fmt.Sprintf("vcert integration test - %d", time.Now().Unix())
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	requestID, err := tpp.RequestCertificate(req, getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req.PickupID = requestID
	req.ChainOption = certificate.ChainOptionIgnore
	_, err = tpp.RetrieveCertificate(req)
	if err == nil {
		t.Fatalf("Error should not be nil, certificate has not been issued.")
	}
}

func TestRevokeCertificate(t *testing.T) {

	cn := "www-1.venqa.venafi.com"

	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration(getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req := &certificate.Request{}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	// req.FriendlyName = fmt.Sprintf("vcert integration test - %d", time.Now().Unix())
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	certDN, err := tpp.RequestCertificate(req, getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	req.PickupID = certDN
	req.ChainOption = certificate.ChainOptionIgnore

	t.Logf("waiting for %s to be ready", certDN)

	var isPending = true
	for isPending {
		t.Logf("%s is pending...", certDN)
		time.Sleep(time.Second * 1)
		_, err = tpp.RetrieveCertificate(req)
		_, isPending = err.(endpoint.ErrCertificatePending)
	}
	if err != nil {
		t.Fatalf("Error should not be nil, certificate has not been issued.")
	}

	t.Logf("Start revocation for %s", certDN)
	revReq := &certificate.RevocationRequest{CertificateDN: certDN, Disable: false}
	err = tpp.RevokeCertificate(revReq)
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestRevokeNonIssuedCertificate(t *testing.T) {

	cn := "does-not-exist.venqa.venafi.com"

	certDN := fmt.Sprintf(`\VED\Policy\%s\%s`, ctx.TPPZone, cn)

	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	revReq := &certificate.RevocationRequest{CertificateDN: certDN, Disable: false}
	err = tpp.RevokeCertificate(revReq)
	if err == nil {
		t.Fatalf("It should NOT revoke certificate at %s which doesn't exist", certDN)
	}
}

func TestRevokeAndDisableCertificate(t *testing.T) {

	cn := test.RandCN()

	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration(getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req := &certificate.Request{}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	// req.FriendlyName = fmt.Sprintf("vcert integration test - %d", time.Now().Unix())
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	certDN, err := tpp.RequestCertificate(req, getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	t.Logf("waiting for %s to be ready", certDN)

	var isPending = true
	for isPending {
		t.Logf("%s is pending...", certDN)
		time.Sleep(time.Second * 1)

		req.PickupID = certDN
		req.ChainOption = certificate.ChainOptionIgnore

		_, err = tpp.RetrieveCertificate(req)
		_, isPending = err.(endpoint.ErrCertificatePending)
	}
	if err != nil {
		t.Fatalf("Error should not be nil, certificate has not been issued.")
	}

	t.Logf("Start revocation for %s", certDN)
	revReq := &certificate.RevocationRequest{CertificateDN: certDN, Disable: true}
	err = tpp.RevokeCertificate(revReq)
	if err != nil {
		t.Fatalf("%s", err)
	}

	t.Logf("trying to enroll %s again after revoked with Disable=true", certDN)
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	certDN, err = tpp.RequestCertificate(req, getPolicyDN(ctx.TPPZone))
	if err == nil {
		t.Fatalf("Certificate/Request should return error if DN has been revoked with Disable=true")
	}
}

func TestRenewCertificate(t *testing.T) {

	cn := test.RandCN()

	tpp := getTestConnector()
	err := tpp.SetBaseURL(ctx.TPPurl)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration(getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req := &certificate.Request{}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	req.CsrOrigin = certificate.ServiceGeneratedCSR
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	certDN, err := tpp.RequestCertificate(req, getPolicyDN(ctx.TPPZone))
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	oldCert := func(certDN string) *x509.Certificate {
		req := &certificate.Request{}
		req.PickupID = certDN
		var isPending = true
		var pcc *certificate.PEMCollection
		for isPending {
			t.Logf("%s is pending...", certDN)
			time.Sleep(time.Second * 1)
			pcc, err = tpp.RetrieveCertificate(req)
			_, isPending = err.(endpoint.ErrCertificatePending)
		}
		if err != nil {
			t.Fatalf("certificate has not been issued: %s", err)
		}

		p, _ := pem.Decode([]byte(pcc.Certificate))
		oldCert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return oldCert
	}(certDN)

	t.Logf("retrieved certificate, Serial is %s", oldCert.SerialNumber)

	renewByCertificateDN := &certificate.RenewalRequest{CertificateDN: certDN}
	reqId1, err := tpp.RenewCertificate(renewByCertificateDN)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("requested renewal for %s, will pickup by %s", certDN, reqId1)

	newCert := func(certDN string) *x509.Certificate {
		req := &certificate.Request{}
		req.PickupID = certDN
		var isPending = true
		var pcc *certificate.PEMCollection
		for isPending {
			t.Logf("%s is pending...", certDN)
			time.Sleep(time.Second * 1)
			pcc, err = tpp.RetrieveCertificate(req)
			_, isPending = err.(endpoint.ErrCertificatePending)
		}
		if err != nil {
			t.Fatalf("certificate has not been issued: %s", err)
		}

		p, _ := pem.Decode([]byte(pcc.Certificate))
		oldCert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return oldCert
	}(reqId1)

	t.Logf("retrieved certificate, Serial is %s", newCert.SerialNumber)

	if newCert.SerialNumber == oldCert.SerialNumber {
		t.Fatal("old and new certificates' serial numbers should not be equal")
	}
}

const crt = `-----BEGIN CERTIFICATE-----
MIIDdjCCAl6gAwIBAgIRAPqSZQ04IjWgO2rwIDRcOY8wDQYJKoZIhvcNAQENBQAw
gYAxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRcwFQYDVQQHDA5TYWx0IExh
a2UgQ2l0eTEPMA0GA1UECgwGVmVuYWZpMRswGQYDVQQLDBJOT1QgRk9SIFBST0RV
Q1RJT04xGzAZBgNVBAMMElZDZXJ0IFRlc3QgTW9kZSBDQTAeFw0xODA5MTIxMzUw
MzNaFw0xODEyMTExMzUwMzNaMCQxIjAgBgNVBAMTGWltcG9ydC52ZW5hZmkuZXhh
bXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQChjQk0jSE5
ktVdH8bAM0QCpGs1rOOVMmRkMc7d4hQ6bTlFlIypMq9t+1O2Z8i4fiKDS7vSBmBo
WBgN9e0fbAnKEvBIcNLBS4lmwzRDxDCrNV3Dr5s+yJtUw9V2XBwiXbtW7qs5+c0O
y7a2S/5HudXUlAuXf7SF4MboMMpHRg+UkyA4j0peir8PtmlJjlYBt3lZdaeLlD6F
EIlIVQFZ6ulUF/kULhxhTUl2yNUUzJ/bqJlhFU6pkL+GoW1lnaZ8FYXwA1EKYyRk
DYL581eqvIBJY9tCNWbOdU1r+5wR4OOKe/WWWhcDC6nL/M8ZYhfQg1nHoD58A8Dk
H4AAt8A3EZpdAgMBAAGjRjBEMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwHwYDVR0jBBgwFoAUzqRFDvLX0mz4AjPb45tLGavm8AcwDQYJKoZIhvcN
AQENBQADggEBABa4wqh+A63O5PHrdUCBSmQs9ve/oIXj561VBmqXkTHLrtKtbtcA
yvsMi8RD8BibBAsUCljkCmLoQD/XeQFtsPlMAxisSMYhChh58008CIYDR8Nf/qoe
YfzdMB/3VWCqTn9KGF8aMKeQvbFvuqmbtdCv//eYe6mNe2fa/x6PSdGMi4BPmjUC
PmBT4p1iwMtu8LnL4UM4awjmmExR4X4rafcyGEbf0D/CRfhDLSwxvrrVcWd6TMMY
HPZ/pw//+UrVLgEEsyM2zwf+LokbszPBvPAtHMJtr7Pnq2MQtEEkLfPqOWG3ol1H
t+4v2LIW1q4GkwOUjPqgyIaJC5jj5pH9/g8=
-----END CERTIFICATE-----`

const pk = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAoY0JNI0hOZLVXR/GwDNEAqRrNazjlTJkZDHO3eIUOm05RZSM
qTKvbftTtmfIuH4ig0u70gZgaFgYDfXtH2wJyhLwSHDSwUuJZsM0Q8QwqzVdw6+b
PsibVMPVdlwcIl27Vu6rOfnNDsu2tkv+R7nV1JQLl3+0heDG6DDKR0YPlJMgOI9K
Xoq/D7ZpSY5WAbd5WXWni5Q+hRCJSFUBWerpVBf5FC4cYU1JdsjVFMyf26iZYRVO
qZC/hqFtZZ2mfBWF8ANRCmMkZA2C+fNXqryASWPbQjVmznVNa/ucEeDjinv1lloX
Awupy/zPGWIX0INZx6A+fAPA5B+AALfANxGaXQIDAQABAoIBAE7of6WOhbsEcHkz
CzZYFBEiVEd8chEu8wBJn9ybD/xV21KUM3x1iGC1EPeYi98ppRvygwQcHzz4Qo+X
HsJpWAK+62TGzvqhNbTfBglPq+IEiA8MGE07WTu3B+3vIcLbe6UDoNkJndJrSIyU
Y9iO+dYClgLi2r9FwoIpSrQzkWqlB3edle4Nq1WABtWTOSDYysz1gk0KrLmQQfXP
CPiwkL0SjB+sfbOiVX0B2liV2oxJ5VZWNo/250wFcvrcYrgTNtEVNMXtpN0tnRMH
NPwnY+B9WGu/NVhtvOcOTPHq9xQhbmBCS1axikizCaIqEOyegdeDJ4ASJnVybfCA
KzjoCpUCgYEAwOmeEvzSP8hCKtLPU8QDBA1y+mEvZMwBY4qr3hfqv3qa0QmFvxkk
7Ubmy2oFOoUnVgnhRzAf/bajbkz4ScUgd2JrUdIEhNNVwDn/llnS/UHBlZY++BtW
mvyon9ObXgPNPoHcJqzrqARu8PPJQEsZ+xjxM/gyif3prn6Uct6R8B8CgYEA1mHd
Astwht39z16FoX9rQRGgx64Z0nesfTjl+4mkypz6ukkcfU1GjobqEG3k666+OJk1
SRs8s20Pahrh21LO5x/QtvChhZ+nIedqlhBlNH9uUJI9ChbUN0luetiSPT8F5aqg
gZMY13K5icAQ+98EcNwl7ZhVPq0BvLlbqTWi9gMCgYEAjtVqoQxob6lKtIJZ19+t
i/aZRyFmAe+6p4UpM8vpl9SjhFrUmGV5neV9ROc+79FfCqlOD3NmfGgaIbUDsTsv
irVoWLBzgBUpzKYkw6HGQpXJS4RvIyy6tw6Tm6MFylpuQPXNlyU5ZrHBos4eGGiC
2BPjo2MFqH5D41r9dv+sdmkCgYEAtSJYx3y2pe04/xYhGFP9fivzyeMrRC4DWoZR
oxcoWl0KZ41QefppzBDoAVuo2Q17AX1JjWxq/DsAlCkEffhYguXZxkhIYQuE/lt2
LjbKG/IzdfYphrXFNrVfmIIWBZOTWvqwxOpRSfBQHbhfYUCMkwMfNMHJ/LvWxOtk
K/L6rpsCgYB6p9RU2kXexAh9kUpbGqVeJBoIh6ArXHgepESE/7dPw26D0DM0mef0
X1MasxN3JF7ZsSGfcCLXnICSJHuNTy9WztqF3hUbQwYd9vmZxtzAo5/fK4DVAaXS
ZtIVl/CH/az0xqLKWIlmWOip9SfUVlZdgege+PlQtRqoFVOsH8+MEg==
-----END RSA PRIVATE KEY-----`

func TestImportCertificate(t *testing.T) {

	tpp := getTestConnector()

	tpp.SetBaseURL(ctx.TPPurl)
	err := tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	importReq := &certificate.ImportRequest{
		// PolicyDN should be like "\\VED\\Policy\\devops\\vcert", or empty (c.zone is used then)
		PolicyDN:             getPolicyDN(ctx.TPPZone),
		ObjectName:           "import.venafi.example.com",
		CertificateData:      crt,
		PrivateKeyData:       pk,
		Reconcile:            false,
		CASpecificAttributes: map[string]string{"a": "42"},
	}

	pp(importReq)

	importResp, err := tpp.ImportCertificate(importReq)
	if err != nil {
		t.Fatalf("failed to import certificate: %s", err)
	}

	pp(importResp)
}

func pp(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(string(b))
}
