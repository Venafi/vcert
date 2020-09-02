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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	if ctx.TPPurl == "" {
		fmt.Println("TPP URL cannot be empty. See Makefile")
		os.Exit(1)
	}

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		panic(err)
	}

	resp, err := tpp.GetRefreshToken(&endpoint.Authentication{
		User: ctx.TPPuser, Password: ctx.TPPPassword,
		Scope: "certificate:discover,manage,revoke;configuration"})
	if err != nil {
		panic(err)
	}

	ctx.TPPRefreshToken = resp.Refresh_token
	ctx.TPPaccessToken = resp.Access_token
}

func getTestConnector(url string, zone string) (c *Connector, err error) {
	c, err = NewConnector(url, zone, false, nil)
	return c, err
}

func TestNewConnectorURLSuccess(t *testing.T) {
	tests := map[string]string{
		"http":                  "http://example.com",
		"https":                 "https://example.com",
		"host_path_only":        "example.com/vedsdk/",
		"trailing_vedsdk":       "https://example.com/vedsdk",
		"trailing_vedsdk_slash": "https://example.com/vedsdk/",
		"upper_case":            "HTTPS://EXAMPLE.COM/VEDSDK/",
		"mixed_case":            "https://EXAMPLE.com/vedsdk/",
	}
	for label, urlString := range tests {
		t.Run(label, func(t *testing.T) {
			c, err := NewConnector(urlString, "", false, nil)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if c == nil {
				t.Fatal("unexpected nil connector")
			}
			u, err := url.Parse(c.baseURL)
			if err != nil {
				t.Errorf("failed to parse baseURL: %v", err)
			}
			if u.Scheme != "https" {
				t.Errorf("unexpected URL scheme: %v", u.Scheme)
			}
			if !strings.HasSuffix(u.Path, "/") {
				t.Errorf("missing trailing slash: %v", u.Path)
			}
			if strings.HasSuffix(u.Path, "vedsdk/") {
				t.Errorf("unstripped vedsdk: %v", u.Path)
			}
		})
	}
}

func TestNewConnectorURLErrors(t *testing.T) {
	tests := map[string]string{
		"empty":          "",
		"bad_scheme":     "ftp://example.com",
		"schemaless":     "//example.com",
		"trailing_other": "https://example.com/foo/",
		"nested_vedsdk":  "https://example.com/foo/vedsdk",
	}
	for label, url := range tests {
		t.Run(label, func(t *testing.T) {
			c, err := NewConnector(url, "", false, nil)
			if err == nil {
				t.Error("expected an error")
			}
			if c != nil {
				t.Error("expected nil connector")
			}
			if !errors.Is(err, verror.UserDataError) {
				t.Errorf("expected a UserDataError, got: %v", err)
			}
		})
	}
}

func TestAuthenticateAuthError(t *testing.T) {
	// An attempt to Authenticate with invalid credentials results in an
	// AuthError.
	// TODO: Test that all Authenticate errors wrap verrors.AuthError
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
	}
	err = tpp.Authenticate(&endpoint.Authentication{
		User:     "invalid-user",
		Password: "invalid-password",
	})
	if err == nil {
		t.Fatalf("expected an error")
	}
	if !errors.Is(err, verror.AuthError) {
		t.Errorf("expected AuthError, got %v", err)
	}
}

func TestPingTPP(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
	}
	err = tpp.Ping()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
}

func TestBadPingTPP(t *testing.T) {
	tpp, err := getTestConnector("http://bonjo-w10dev:333/vedsdk/", ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: http://bonjo-w10dev:333/vedsdk/", err)
	}
	err = tpp.Ping()
	if err == nil {
		t.Fatalf("err should not be nil, URL does not exist")
	}
}

func TestGetRefreshToken(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, "")
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	refreshToken, err := tpp.GetRefreshToken(&endpoint.Authentication{
		User: ctx.TPPuser, Password: ctx.TPPPassword,
		Scope: "certificate:discover,manage,revoke", ClientId: "vcert-sdk"})
	if err != nil {
		t.Fatalf("%s", err)
	}

	err = tpp.Authenticate(&endpoint.Authentication{AccessToken: refreshToken.Access_token})
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	tpp.SetZone(ctx.TPPZone)
	_, err = tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestGetRefreshTokenWithDefaultScope(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	refreshToken, err := tpp.GetRefreshToken(&endpoint.Authentication{
		User: ctx.TPPuser, Password: ctx.TPPPassword})
	if err != nil {
		t.Fatalf("%s", err)
	}

	if refreshToken.Scope != defaultScope {
		t.Fatalf("Scope from refresh roken %s is not as default scope %s;", refreshToken.Scope, defaultScope)
	}
	err = tpp.Authenticate(&endpoint.Authentication{AccessToken: refreshToken.Access_token})
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	tpp.SetZone(ctx.TPPZone)
	_, err = tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}
}

func TestFailRefreshAccessToken(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}
	auth := &endpoint.Authentication{RefreshToken: "WRONGREFRESHTOKEN", ClientId: ctx.ClientID}
	err = tpp.Authenticate(auth)
	if err == nil {
		t.Fatalf("err should not be nil, er")
	}

	if !strings.Contains(err.Error(), "unexpected status code on TPP Authorize. Status: 400") {
		t.Fatalf("error text should contain: 'unexpected status code on TPP Authorize. Status: 400'. but it is: '%s'", err)
	}
}

func TestRefreshAccessToken(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, "")
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	auth := &endpoint.Authentication{RefreshToken: ctx.TPPRefreshToken, ClientId: ctx.ClientID}
	err = tpp.Authenticate(auth)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	tpp.SetZone(ctx.TPPZone)
	_, err = tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}

	//Uppdate refresh token for further tests
	ctx.TPPRefreshToken = auth.RefreshToken

}

func TestRefreshAccessTokenNoClientID(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}
	auth := &endpoint.Authentication{RefreshToken: ctx.TPPRefreshToken}
	err = tpp.Authenticate(auth)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	tpp.SetZone(ctx.TPPZone)
	_, err = tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}

	//Update tokens for further tests
	ctx.TPPRefreshToken = auth.RefreshToken
	ctx.TPPaccessToken = tpp.accessToken

}

func TestAuthenticationAccessToken(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	tpp.SetZone(ctx.TPPZone)
	_, err = tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("%s", err)
	}

	err = tpp.Authenticate(&endpoint.Authentication{AccessToken: "WRONGm3XPAT5nlWxd3iA=="})
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	tpp.SetZone(ctx.TPPZone)
	_, err = tpp.ReadZoneConfiguration()
	if err == nil {
		t.Fatalf("Auth with wrong token should fail")
	}

}

func TestAuthorizeToTPP(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
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
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
	}
	err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: "wrongPassword"})
	if err == nil {
		t.Fatalf("err should not be nil, bad password was used")
	}
}

func TestReadConfigData(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	testCases := []struct {
		zone       string
		zoneConfig endpoint.ZoneConfiguration
	}{
		{getPolicyDN(ctx.TPPZone), endpoint.ZoneConfiguration{
			Organization:          "Venafi Inc.",
			OrganizationalUnit:    []string{"Integrations"},
			Country:               "US",
			Province:              "Utah",
			Locality:              "Salt Lake",
			HashAlgorithm:         x509.SHA256WithRSA,
			KeyConfiguration:      &endpoint.AllowedKeyConfiguration{KeySizes: []int{2048}},
			CustomAttributeValues: make(map[string]string),
		}},
		{getPolicyDN(ctx.TPPZoneRestricted), endpoint.ZoneConfiguration{
			Organization:          "Venafi Inc.",
			OrganizationalUnit:    []string{"Integration"},
			Country:               "US",
			Province:              "Utah",
			Locality:              "Salt Lake",
			HashAlgorithm:         x509.SHA256WithRSA,
			KeyConfiguration:      &endpoint.AllowedKeyConfiguration{KeySizes: []int{2048}},
			CustomAttributeValues: make(map[string]string),
		}},
	}
	for _, c := range testCases {
		tpp.SetZone(c.zone)
		zoneConfig, err := tpp.ReadZoneConfiguration()
		if err != nil {
			t.Fatalf("%s", err)
		}
		zoneConfig.Policy = endpoint.Policy{}
		if err != nil {
			t.Fatalf("%s", err)
		}
		if !reflect.DeepEqual(*zoneConfig, c.zoneConfig) {
			t.Fatalf("zone config for zone %s is not as expected \nget:    %+v \nexpect: %+v", c.zone, *zoneConfig, c.zoneConfig)
		}
	}
	tpp.SetZone("Wrong Zone")
	_, err = tpp.ReadZoneConfiguration()
	if err == nil {
		t.Fatalf("err should be not nil for not existed zone")
	}
}

func TestBadReadConfigData(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, "notexistedzone")
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	_, err = tpp.ReadZoneConfiguration()
	if err == nil {
		t.Fatalf("err should not be nil, invalid policy was used")
	}
}

func TestRequestCertificateUserPassword(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{User: ctx.TPPuser, Password: ctx.TPPPassword})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	DoRequestCertificate(t, tpp)
}

func TestRequestCertificateToken(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	DoRequestCertificate(t, tpp)
}

func DoRequestCertificate(t *testing.T, tpp *Connector) {
	config, err := tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	cn := test.RandCN()
	req := &certificate.Request{Timeout: time.Second * 30}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	u := url.URL{Scheme: "https", Host: "example.com", Path: "/test"}
	req.URIs = []*url.URL{&u}
	req.FriendlyName = cn
	req.CustomFields = []certificate.CustomField{
		{Name: "custom", Value: "2019-10-10"},
	}
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	t.Logf("getPolicyDN(ctx.TPPZone) = %s", getPolicyDN(ctx.TPPZone))
	req.PickupID, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	certCollections, err := tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode([]byte(certCollections.Certificate))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	if cert.Subject.CommonName != cn {
		t.Fatalf("mismatched common names: %v and %v", cn, cert.Subject.CommonName)
	}
	if cert.URIs[0].String() != u.String() {
		t.Fatalf("mismatched URIs: %v and %v", u.String(), cert.URIs[0].String())
	}
}

func TestRequestCertificateServiceGenerated(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	config, err := tpp.ReadZoneConfiguration()
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

	pickupId, err := tpp.RequestCertificate(req)
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
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration()
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

	requestID, err := tpp.RequestCertificate(req)
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

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration()
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

	certDN, err := tpp.RequestCertificate(req)
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
		t.Fatalf("Error should not be nil, certificate has not been issued. err: %s", err)
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

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
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

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration()
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

	certDN, err := tpp.RequestCertificate(req)
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

	certDN, err = tpp.RequestCertificate(req)
	if err == nil {
		t.Fatalf("Certificate/Request should return error if DN has been revoked with Disable=true")
	}
}

func TestRenewCertificate(t *testing.T) {

	cn := test.RandCN()

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration()
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

	certDN, err := tpp.RequestCertificate(req)
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

func TestRenewCertRestoringValues(t *testing.T) {
	cn := test.RandCN()
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZoneECDSA)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	req := &certificate.Request{}
	req.Subject.CommonName = cn
	req.Subject.Organization = []string{"Venafi, Inc."}
	req.Subject.OrganizationalUnit = []string{"Automated Tests"}
	req.Subject.Locality = []string{"Las Vegas"}
	req.Subject.Province = []string{"Nevada"}
	req.Subject.Country = []string{"US"}
	req.KeyType = certificate.KeyTypeECDSA
	req.KeyCurve = certificate.EllipticCurveP521
	req.CsrOrigin = certificate.LocalGeneratedCSR
	req.Timeout = time.Second * 10
	err = tpp.GenerateRequest(&endpoint.ZoneConfiguration{}, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	_, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	pcc, err := tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := pem.Decode([]byte(pcc.Certificate))
	oldCert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, ok := oldCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("bad key type")
	}
	if oldKey.Curve.Params().Name != "P-521" {
		t.Fatalf("bad curve %v", oldKey.Curve.Params().Name)
	}
	renewReq := certificate.RenewalRequest{
		CertificateDN: req.PickupID,
	}
	pickupdID, err := tpp.RenewCertificate(&renewReq)
	if err != nil {
		t.Fatal(err)
	}
	req = &certificate.Request{PickupID: pickupdID, Timeout: 30 * time.Second}
	pcc, err = tpp.RetrieveCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	p, _ = pem.Decode([]byte(pcc.Certificate))
	newCert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	newKey, ok := newCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("bad key type")
	}
	if newKey.Curve.Params().Name != "P-521" {
		t.Fatalf("bad curve %v", newKey.Curve.Params().Name)
	}
	//todo: uncomment after renew refactoring
	//if string(oldKey.X.Bytes()) == string(newKey.X.Bytes()) || string(oldKey.Y.Bytes()) == string(newKey.Y.Bytes()) {
	//	t.Fatal("key reuse")
	//}
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

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	importReq := &certificate.ImportRequest{
		// PolicyDN should be like "\\VED\\Policy\\devops\\vcert", or empty (c.zone is used then)
		PolicyDN:        getPolicyDN(ctx.TPPZone),
		ObjectName:      "import12348.venafi.example.com",
		CertificateData: crt,
		PrivateKeyData:  pk,
		Reconcile:       false,
	}

	pp(importReq)

	importResp, err := tpp.ImportCertificate(importReq)
	if err != nil {
		t.Fatalf("failed to import certificate: %s", err)
	}

	pp(importResp)
}

func TestReadPolicyConfiguration(t *testing.T) {
	//todo: add more zones tests
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	cases := []struct {
		zone   string
		policy endpoint.Policy
	}{
		{
			ctx.TPPZone, // todo: replace with env variable
			endpoint.Policy{
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]endpoint.AllowedKeyConfiguration{
					{certificate.KeyTypeRSA, certificate.AllSupportedKeySizes(), nil},
					{certificate.KeyTypeECDSA, nil, certificate.AllSupportedCurves()},
				},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				true,
				true,
			},
		},
		{
			ctx.TPPZoneRestricted,
			endpoint.Policy{
				[]string{`^([\p{L}\p{N}-*]+\.)*vfidev\.com$`, `^([\p{L}\p{N}-*]+\.)*vfidev\.net$`, `^([\p{L}\p{N}-*]+\.)*vfide\.org$`},
				[]string{`^Venafi Inc\.$`},
				[]string{"^Integration$"},
				[]string{"^Utah$"},
				[]string{"^Salt Lake$"},
				[]string{"^US$"},
				[]endpoint.AllowedKeyConfiguration{{certificate.KeyTypeRSA, []int{2048, 4096, 8192}, nil}},
				[]string{`^([\p{L}\p{N}-*]+\.)*vfidev\.com$`, `^([\p{L}\p{N}-*]+\.)*vfidev\.net$`, `^([\p{L}\p{N}-*]+\.)*vfide\.org$`},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				true,
				true,
			},
		},
		{
			ctx.TPPZoneECDSA,
			endpoint.Policy{
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]endpoint.AllowedKeyConfiguration{
					{certificate.KeyTypeECDSA, nil, []certificate.EllipticCurve{certificate.EllipticCurveP521}},
				},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				[]string{".*"},
				true,
				true,
			},
		},
	}
	for _, c := range cases {
		tpp.SetZone(c.zone)
		policy, err := tpp.ReadPolicyConfiguration()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(*policy, c.policy) {
			t.Fatalf("policy for zone %s is not as expected \nget:    %+v \nexpect: %+v", c.zone, *policy, c.policy)
		}
	}
}
func pp(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(string(b))
}

func Test_EnrollDoesntChange(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	config, err := tpp.ReadZoneConfiguration()
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

	req.PrivateKey = pemRSADecode([]byte(pk))

	req.FriendlyName = cn
	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	t.Logf("getPolicyDN(ctx.TPPZone) = %s", getPolicyDN(ctx.TPPZone))
	_, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}
	privKey, ok := req.PrivateKey.(*rsa.PrivateKey)
	fmt.Println(privKey.D.Bytes())
	if !ok || privKey.D.Cmp(pemRSADecode([]byte(pk)).D) != 0 {
		t.Fatal("key before and key after requesting don`t match")
	}
}

func pemRSADecode(priv []byte) *rsa.PrivateKey {
	privPem, _ := pem.Decode(priv)

	parsedKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		panic(err)
	}
	return parsedKey
}

func TestNormalizeURL(t *testing.T) {
	url := "http://localhost/vedsdk/"
	modifiedURL, err := normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(modifiedURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, modifiedURL)
	}

	url = "http://localhost"
	modifiedURL = ""
	modifiedURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(modifiedURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, modifiedURL)
	}

	url = "http://localhost/vedsdk"
	modifiedURL = ""
	modifiedURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(modifiedURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, modifiedURL)
	}

	url = "localhost/vedsdk"
	modifiedURL = ""
	modifiedURL, err = normalizeURL(url)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, url)
	}
	if !strings.EqualFold(modifiedURL, expectedURL) {
		t.Fatalf("Base URL did not match expected value. Expected: %s Actual: %s", expectedURL, modifiedURL)
	}

	url = "ftp://wrongurlformat.com"
	modifiedURL = ""
	modifiedURL, err = normalizeURL(url)
	if err == nil {
		t.Fatalf("err was not expected to be nil. url: %s", url)
	}
	if strings.EqualFold(modifiedURL, expectedURL) {
		t.Fatalf("Base URL should not match expected value. Expected: %s Actual: %s", expectedURL, modifiedURL)
	}
}

func Test_GetCertificateList(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}
	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	for _, count := range []int{10, 100, 101, 153, 200, 2000} {
		timeStarted := time.Now()
		l, err := tpp.ListCertificates(endpoint.Filter{Limit: &count})
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
			t.Errorf("mismatched certificates number: wait %d, got %d", count, len(set))
		}
	}
}

func Test_GetCertificateListFull(t *testing.T) {
	const certPem = `-----BEGIN CERTIFICATE-----
MIICZjCCAcegAwIBAgIIe1Dq0CjsAx8wCgYIKoZIzj0EAwQwEjEQMA4GA1UEAxMH
VGVzdCBDQTAeFw0xOTExMjAxNDU3MDBaFw0xOTExMjYxNDUwMDBaMHoxCzAJBgNV
BAYTAlVTMQ0wCwYDVQQIEwRVdGFoMRIwEAYDVQQHEwlTYWx0IExha2UxFDASBgNV
BAoTC1ZlYW5maSBJbmMuMRQwEgYDVQQLEwtJbnRlZ3JhdGlvbjEcMBoGA1UEAxMT
ZXhwaXJlZDEudmZpZGV2LmNvbTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAWNR
bh7m40QpJAMV9DQMFQA6ZwIwQpBZp470b4pWt5Ih+64oLHMgwDTOkjv701hCYWK0
BdxNXYCpEGvnA3BahHprAaQHsDWxHygKJdtNeGW8ein7hN1CdMtm72aFp5DHI82U
jDWQHczRatUpOEdzjB+9JwYtI1BIFTVA8xvpRrQwEqwio1wwWjAMBgNVHRMBAf8E
AjAAMB0GA1UdDgQWBBSgTpxmCxUnyqB/xpXevPcQklFtxDALBgNVHQ8EBAMCBeAw
HgYDVR0RBBcwFYITZXhwaXJlZDEudmZpZGV2LmNvbTAKBggqhkjOPQQDBAOBjAAw
gYgCQgFrpA/sLEzrWumVicNJGLHFK2FhhMxOxOeC1Fk3HTJDiMfxHMe1QBP++wLp
vOjeQhOnqrPdQINzUCKMSuqxqFGbQAJCAZs3Be1Pz6eeKHNLzr7mYQ2/pWSjfun4
45nAry0Rb308mXI49fEprVJDQ0zyb3gM8Z8OA0wDyaQ+pcwloQkvOAM2
-----END CERTIFICATE-----
`
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZoneRestricted)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}
	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	importReq := certificate.ImportRequest{CertificateData: certPem}
	_, err = tpp.ImportCertificate(&importReq)
	if err != nil {
		t.Fatal(err)
	}
	validList, err := tpp.ListCertificates(endpoint.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	fullList, err := tpp.ListCertificates(endpoint.Filter{WithExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(validList) >= len(fullList) {
		t.Fatalf("valid certificates numbe (%v) should be less than all certificates number (%v)", len(validList), len(fullList))
	}
	req := certificate.Request{Subject: pkix.Name{CommonName: fmt.Sprintf("test%d%d.vfidev.com", time.Now().Unix(), time.Now().Nanosecond())}, KeyType: certificate.KeyTypeRSA, KeyLength: 2048}

	err = tpp.GenerateRequest(nil, &req)
	if err != nil {
		t.Fatal(err)
	}

	req.PickupID, err = tpp.RequestCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second * 10) //todo: remove after fix bug VEN-54714
	validList2, err := tpp.ListCertificates(endpoint.Filter{})
	if err != nil {
		t.Fatal(err)
	}
	fullList2, err := tpp.ListCertificates(endpoint.Filter{WithExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(fullList)+1 != len(fullList2) {
		t.Fatal("list should be longer")
	}

	if len(validList)+1 != len(validList2) {
		t.Fatal("list should be longer")
	}

}

func TestEnrollWithLocation(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	cn := test.RandCN()
	zoneConfig, err := tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatal(err)
	}

	workload := fmt.Sprintf("workload-%v", time.Now().Unix())

	req := certificate.Request{}
	req.Subject.CommonName = cn
	req.Timeout = time.Second * 10
	req.Location = &certificate.Location{
		Instance:   "instance",
		Workload:   workload,
		TLSAddress: "example.com:443",
	}

	err = tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpp.RequestCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}
	req = certificate.Request{}
	req.Subject.CommonName = cn
	req.Timeout = time.Second * 10
	req.Location = &certificate.Location{
		Instance:   "instance",
		Workload:   workload,
		TLSAddress: "example.com:443",
	}

	err = tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpp.RequestCertificate(&req)
	if err == nil {
		t.Fatal("Should fail with devices conflict")
	}
	req = certificate.Request{}
	req.Subject.CommonName = cn
	req.Timeout = time.Second * 10
	req.Location = &certificate.Location{
		Instance:   "instance",
		Workload:   workload,
		TLSAddress: "example.com:443",
		Replace:    true,
	}

	err = tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tpp.RequestCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}

	//request same certificate with different workload but without replace
	req.Location = &certificate.Location{
		Instance:   "instance",
		Workload:   workload + "-1",
		TLSAddress: "example.com:443",
		Replace:    false,
	}

	err = tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tpp.RequestCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}

	//request same certificate with same workload and without replace
	req.Location = &certificate.Location{
		Instance:   "instance",
		Workload:   workload + "-1",
		TLSAddress: "example.com:443",
		Replace:    false,
	}

	err = tpp.GenerateRequest(zoneConfig, &req)
	if err != nil {
		t.Fatal(err)
	}

	_, err = tpp.RequestCertificate(&req)
	if err == nil {
		t.Fatal("There should be a error if we're trying to set same device twice in location")
	}
	expected_message := "vcert error: your data contains problems: instance"
	if !strings.Contains(err.Error(), expected_message) {
		t.Fatalf("We should exit with error message '%s' if we're trying to set same device twice in location. But we vcert exited with error: %s", expected_message, err)
	}

	//TODO: test that only instance from parameters is dissociated
	//TODO: test app info with different kind of strings ???
	//TODO: Check origin using config/read post request example:
	//{
	//   "ObjectDN":"\\VED\\Policy\\devops\\vcert\\1582237636-pgqlx.venafi.example.com",
	//   "AttributeName":"Origin"
	//}
}

func TestOmitSans(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, expectedURL)
	}
	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}
	zone, err := tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatal(err)
	}
	cn := test.RandCN()

	req := certificate.Request{
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyLength: 2048,
		DNSNames:  []string{"www." + cn, cn},
		OmitSANs:  true,
		CsrOrigin: certificate.ServiceGeneratedCSR,
		Timeout:   30 * time.Second,
	}

	tppReq, err := prepareRequest(&req, tpp.zone)
	if err != nil {
		t.Fatal(err)
	}
	if len(tppReq.SubjectAltNames) > 0 {
		t.Fatal("certificate should have 0 SANs")
	}

	req = certificate.Request{
		Subject: pkix.Name{
			CommonName: cn,
		},
		KeyLength: 2048,
		DNSNames:  []string{"www." + cn, cn},
		OmitSANs:  true,
		CsrOrigin: certificate.LocalGeneratedCSR,
		Timeout:   30 * time.Second,
	}
	err = tpp.GenerateRequest(zone, &req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(req.GetCSR())
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.DNSNames) > 0 {
		t.Fatal("certificate should have 0 SANs")
	}
	_, err = tpp.RequestCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tpp.RetrieveCertificate(&req)
	if err != nil {
		t.Fatal(err)
	}
}
