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
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"github.com/Venafi/vcert/v4/test"
)

var ctx *test.Context

func init() {
	ctx = test.GetEnvContext()
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		Renegotiation:      tls.RenegotiateFreelyAsClient,
		InsecureSkipVerify: true}

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
		Scope: "certificate:discover,manage,revoke;configuration:manage;ssh:manage"})
	if err != nil {
		panic(err)
	}

	ctx.TPPRefreshToken = resp.Refresh_token
	ctx.TPPaccessToken = resp.Access_token
}

func getTestConnector(url string, zone string) (c *Connector, err error) {
	c, err = NewConnector(url, zone, false, nil)
	c.client = &http.Client{}
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

func TestRetrieveSystemVersion(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, "")
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
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

	serviceVersion, err := tpp.RetrieveSystemVersion()
	if err != nil {
		t.Fatalf("Failed to get Venafi system version. Error: %v", err)
	}

	if serviceVersion == "" {
		t.Fatalf("Failed to get Venafi system version. Error: %v", err)
	}

	_, err = regexp.MatchString(`^([0-9]{2})(\.[1-4]{1})(\.[0-9]{1,4})+`, serviceVersion)

	if err != nil {
		t.Fatalf("Failed due to Venafi system version's format is invalid. Error: %s", err)
	}
}

func TestRetrieveSelfIdentity(t *testing.T) {
	tpp, err := getTestConnector(ctx.TPPurl, "")
	if err != nil {
		t.Fatalf("err is not nil, err: %s url: %s", err, ctx.TPPurl)
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

	identity, err := tpp.retrieveSelfIdentity()
	if err != nil {
		t.Fatalf("Failed to get the used user. Error: %v", err)
	}

	if identity.Name == "" {
		t.Fatalf("Failed to get to get Self")
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

func TestRequestCertificateWithValidHours(t *testing.T) {
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
	DoRequestCertificateWithValidHours(t, tpp)
}

func Test_shouldReset(t *testing.T) {
	tests := []struct {
		name     string
		givenErr error
		want     bool
	}{
		{
			name:     "nil error",
			givenErr: nil,
			want:     false,
		},
		{
			name:     "error is not a 500",
			givenErr: fmt.Errorf("unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 400 Certificate does not exist."),
			want:     false,
		},
		{
			name:     "error is a 500 but not WebSDK or Click Retry",
			givenErr: fmt.Errorf("unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500."),
			want:     false,
		},
		{
			name:     "error is a 500 and is Click Retry",
			givenErr: fmt.Errorf("unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry., Stage: 500."),
			want:     true,
		},
		{
			name:     "error is a 500 and is WebSDK",
			givenErr: fmt.Errorf("unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: WebSDK CertRequest Module Requested Certificate, Stage: 500."),
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldReset(tt.givenErr)
			if got != tt.want {
				t.Errorf("shouldReset() = %v, want %v", got, tt.want)
			}
		})
	}
}

// The reason we are using a mock HTTP server rather than the live TPP server is
// because consistently triggering the 500 error in a stage different than 0
// requires putting a powershell script on the TPP VM or turning the Microsoft
// CA off, which is not something that can be done as part of the "set up" of
// the current tests we have in vcert.
//
// The HTTP response samples below are based on tests performed manually with a
// TPP 20.1 instance by inspecting the HTTP responses with curl.
func TestRetrieveCertificate(t *testing.T) {
	certData := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlGTWpDQ0JCcWdBd0lCQWdJVEx3QUFBVmVJV0tkUVFTbmRmd0FBQUFBQlZ6QU5CZ2txaGtpRzl3MEJBUXNGDQpBREJOTVJNd0VRWUtDWkltaVpQeUxHUUJHUllEWTI5dE1Sb3dHQVlLQ1pJbWlaUHlMR1FCR1JZS2RtVnVZV1pwDQpaR1Z0YnpFYU1CZ0dBMVVFQXhNUmRtVnVZV1pwWkdWdGJ5MVVVRkF0UTBFd0hoY05Nakl4TVRFME1UVXdOVFU0DQpXaGNOTWpReE1ERTNNVFUxTnpRNVdqQVhNUlV3RXdZRFZRUURFd3hpWlhoaGJYQnNaUzVqYjIwd2dnRWlNQTBHDQpDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRQzAwZE05RjdmNk12RlpZMzgyejQvbFZiRWNROFp2DQp1VkNTL2ovaVpmNkVwbUpjMzdubnlFeDJqSVR4eTNPdXRjMmJVUmZ2a284MmV5cHFieDhlNWNCV3pwUWs0NU5pDQpUdzlhMmFqbGhPbE11c1R2RzRLc29DUGM5K29URHRmb3NvRjRSK05rbjZZa0RFenZUb1pzME5yKy9LcTl4THVPDQpOWkM3d0M1dE5TemJRT01aVVV0NGt0WXZBQkp0dHZENlNrY0Y5ZVMySGRJWFJ3aHhPV05TZjYrcGhKZko4ZnhGDQpKSWJmaU9wMktGRVlEWGJ1L0kzeUpSdHFmY211M2FqV0MyR2NkMkNGaTJxdUJ4SDdCVXZoL1ltTm10K2F5MExJDQphK21PTXduNytZdDhKbVh6TWRIVjZZSEhZanQwR0pyRjBxRlR1bjFIeENGQnRBYU1ITzJVSmZVSEFnTUJBQUdqDQpnZ0kvTUlJQ096QVhCZ05WSFJFRUVEQU9nZ3hpWlhoaGJYQnNaUzVqYjIwd0hRWURWUjBPQkJZRUZQV3d2YmE3DQp4cTVhOWZhNWw3cFRCMlVZcjV2cE1COEdBMVVkSXdRWU1CYUFGSU4xZWxSWUdMZ2lIU2gzdnUzbEtUL1lvZlgrDQpNSUhPQmdOVkhSOEVnY1l3Z2NNd2djQ2dnYjJnZ2JxR2diZHNaR0Z3T2k4dkwwTk9QWFpsYm1GbWFXUmxiVzh0DQpWRkJRTFVOQkxFTk9QWFJ3Y0N4RFRqMURSRkFzUTA0OVVIVmliR2xqSlRJd1MyVjVKVEl3VTJWeWRtbGpaWE1zDQpRMDQ5VTJWeWRtbGpaWE1zUTA0OVEyOXVabWxuZFhKaGRHbHZiaXhFUXoxMlpXNWhabWxrWlcxdkxFUkRQV052DQpiVDlqWlhKMGFXWnBZMkYwWlZKbGRtOWpZWFJwYjI1TWFYTjBQMkpoYzJVL2IySnFaV04wUTJ4aGMzTTlZMUpNDQpSR2x6ZEhKcFluVjBhVzl1VUc5cGJuUXdnY1lHQ0NzR0FRVUZCd0VCQklHNU1JRzJNSUd6QmdnckJnRUZCUWN3DQpBb2FCcG14a1lYQTZMeTh2UTA0OWRtVnVZV1pwWkdWdGJ5MVVVRkF0UTBFc1EwNDlRVWxCTEVOT1BWQjFZbXhwDQpZeVV5TUV0bGVTVXlNRk5sY25acFkyVnpMRU5PUFZObGNuWnBZMlZ6TEVOT1BVTnZibVpwWjNWeVlYUnBiMjRzDQpSRU05ZG1WdVlXWnBaR1Z0Ynl4RVF6MWpiMjAvWTBGRFpYSjBhV1pwWTJGMFpUOWlZWE5sUDI5aWFtVmpkRU5zDQpZWE56UFdObGNuUnBabWxqWVhScGIyNUJkWFJvYjNKcGRIa3dJUVlKS3dZQkJBR0NOeFFDQkJRZUVnQlhBR1VBDQpZZ0JUQUdVQWNnQjJBR1VBY2pBT0JnTlZIUThCQWY4RUJBTUNCYUF3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIDQpBd0V3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUhCWFEwTVdUU1UzcllXTWNMVDBySE5lSVBMSXJoWDNFWGpWDQpmdzIxT1RKL09MWFBFY0lhVTQrWlNUOThpZE5oRG15VkNudmVxaXpzT0tibDdQUFR4OHZrbWUwOFpmS2R1QmNODQpsL1VwOTV2YVZYU0Y4K0k4dUNNd3pQZ3dtclVRYUhkNWl3b1hHOHpmdE5ndGcxdUNqZ2ZNVk1acUVsTmtxWk5QDQpETkpvYUp5U1VzY0ZFTE5FTENDa05IR2EyenZZaDRCMjk0UDY2RlRzdkpZanl6YnkzVTV5RW9HM0RaWmxjMzArDQpJNWZXMlI3K3djcWRvRUV4R1dHZXh0N0QzU0Rqc3RYL2ZiNUV1RG1BS0NIOFZoWmFKdUQ1Qkc3L3AvbC9PaVBxDQp0aGdpcHhXb2VzOEVITERaVWVDS0xQR2lUR3pyZWtvNXdqVWxDaFdkM0Q1MkhBWjFxTTQ9DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tDQo="

	type mockResp struct {
		status string // The HTTP status line, e.g. "400 Bad Request".
		body   string
	}

	tests := []struct {
		name         string
		mockRetrieve []mockResp
		mockReset    mockResp
		givenTimeout time.Duration
		expectErr    string
	}{
		{
			name: "should succeed if cert immediately available",
			mockRetrieve: []mockResp{
				{"200 OK", `{"CertificateData":"` + certData + `","Filename":"bexample.com.cer","Format":"base64"}`},
			},
		},
		{
			name: "should fail when 400",
			mockRetrieve: []mockResp{
				{"400 Certificate does not exist.",
					`{"Error":"Certificate \\VED\\Policy\\Test\\bexample.com does not exist."}`},
			},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 400 Certificate does not exist.",
		},
		{
			name: "should fail when 401",
			mockRetrieve: []mockResp{
				// This is an example of TPP response for which the error
				// can only be found in the body.
				{"401 Unauthorized",
					`{"error": "session_error","error_description": "Invalid token format"}`},
			},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 401 Unauthorized",
		},
		{
			name: "should fail when 403",
			mockRetrieve: []mockResp{
				// This is an example of TPP response for which the error can
				// only be found in the HTTP status line and not in the body.
				{"403 Failed to issue grant: User is not authorized for the requested scope",
					``},
			},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 403 Failed to issue grant: User is not authorized for the requested scope",
		},
		{
			name: "should fail when 'private key'",
			mockRetrieve: []mockResp{
				// This specific error message is relied upon by vcert itself as
				// well as terraform-provider-venafi. So let's make sure we
				// don't break it. See:
				// https://github.com/Venafi/terraform-provider-venafi/blob/5374fa5/venafi/resource_venafi_certificate.go#L821
				{"400 Failed to lookup private key, error: Failed to lookup private key vault id",
					`{"Error":"Failed to lookup private key, error: Failed to lookup private key vault id"}`},
			},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 400 Failed to lookup private key, error: Failed to lookup private key vault id",
		},
		{
			name: "should succeed if cert immediately available regardless of the timeout value",
			mockRetrieve: []mockResp{
				{"200 OK",
					`{"CertificateData":"` + certData + `","Filename":"bexample.com.cer","Format":"base64"}`},
			},
			givenTimeout: 3 * time.Second,
		},
		{
			name: "should fail when cert is still pending and timeout set to 0",
			mockRetrieve: []mockResp{
				{`202 Certificate \VED\Policy\TLS/SSL\aexample.com being processed, Status: Post CSR, Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR"}`},
			},
			expectErr: "Issuance is pending. You may try retrieving the certificate later using Pickup ID: \\VED\\Policy\\Test\\bexample.com\n\tStatus: Post CSR",
		},
		{
			name: "should succeed when cert not available immediately but the timeout is set",
			mockRetrieve: []mockResp{
				{`202 Certificate \VED\Policy\TLS/SSL\aexample.com being processed, Status: Post CSR, Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR"}`},
				{"200 OK",
					`{"CertificateData":"` + certData + `","Filename":"bexample.com.cer","Format":"base64"}`},
			},
			givenTimeout: 3 * time.Second,
		},
		{
			name: "should fail when enrollment immediately fails",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR failed with error: Cannot connect to the certificate authority (CA)."}`},
			},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.",
		},
		{
			name: "should succeed after resetting the msg WebSDK CertRequest",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: WebSDK CertRequest Module Requested Certificate, Stage: 500.`,
					`{"Stage": 500, "Status": "WebSDK CertRequest Module Requested Certificate"}`},
				{`202 Certificate \VED\Policy\TLS/SSL\aexample.com being processed, Status: Post CSR, Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR"}`},
				{`200 OK`,
					`{"CertificateData":"` + certData + `","Filename":"bexample.com.cer","Format":"base64"}`},
			},
			mockReset:    mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
			givenTimeout: 3 * time.Second,
		},
		{
			name: "should fail after resetting msg WebSDK CertRequest and enrollment fails",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: WebSDK CertRequest Module Requested Certificate, Stage: 500.`,
					`{"Stage": 500, "Status": "WebSDK CertRequest Module Requested Certificate"}`},
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR failed with error: Cannot connect to the certificate authority (CA)."}`},
			},
			mockReset: mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.",
		},
		{
			name: "should fail if msg WebSDK shows twice in a row",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: WebSDK CertRequest Module Requested Certificate, Stage: 500.`,
					`{"Stage": 500, "Status": "WebSDK CertRequest Module Requested Certificate"}`},
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: WebSDK CertRequest Module Requested Certificate, Stage: 500.`,
					`{"Stage": 500, "Status": "WebSDK CertRequest Module Requested Certificate"}`},
			},
			mockReset: mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: WebSDK CertRequest Module Requested Certificate, Stage: 500.",
		},
		{
			name: "should fail after resetting msg WebSDK CertRequest when enrollment in progress and timeout is 0",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: WebSDK CertRequest Module Requested Certificate, Stage: 500.`,
					`{"Stage": 500, "Status": "WebSDK CertRequest Module Requested Certificate"}`},
				{`202 Certificate \VED\Policy\TLS/SSL\aexample.com being processed, Status: Post CSR, Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR"}`},
			},
			mockReset: mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
			expectErr: "Issuance is pending. You may try retrieving the certificate later using Pickup ID: \\VED\\Policy\\Test\\bexample.com\n\tStatus: Post CSR",
		},
		{
			name: "should succeed after resetting the msg Click Retry",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry., Stage: 500.`,
					`{"Stage": 500, "Status": "This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry."}`},
				{`200 OK`,
					`{"CertificateData":"` + certData + `","Filename":"bexample.com.cer","Format":"base64"}`},
			},
			mockReset: mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
		},
		{
			name: "should succeed after resetting the msg Click Retry and after waiting",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry., Stage: 500.`,
					`{"Stage": 500, "Status": "This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry."}`},
				{`202 Certificate \VED\Policy\TLS/SSL\aexample.com being processed, Status: Post CSR, Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR"}`},
				{`200 OK`,
					`{"CertificateData":"` + certData + `","Filename":"bexample.com.cer","Format":"base64"}`},
			},
			mockReset:    mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
			givenTimeout: 3 * time.Second,
		},
		{
			name: "should fail when reset fails after msg Click Retry",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry., Stage: 500.`,
					`{"Stage": 500, "Status": "This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry."}`},
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR failed with error: Cannot connect to the certificate authority (CA)."}`},
			},
			mockReset: mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.",
		},
		{
			name: "should fail if msg Click Retry shows twice in a row",
			mockRetrieve: []mockResp{
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry., Stage: 500.`,
					`{"Stage": 500, "Status": "This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry."}`},
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry., Stage: 500.`,
					`{"Stage": 500, "Status": "This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry."}`},
			},
			mockReset: mockResp{`200 OK`, `{"ProcessingResetCompleted": true}`},
			expectErr: "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: This certificate cannot be processed while it is in an error state. Fix any errors, and then click Retry., Stage: 500.",
		},
		{
			name: "should fail when there is a 500 after waiting for the cert",
			mockRetrieve: []mockResp{
				{`202 Certificate \VED\Policy\TLS/SSL\aexample.com being processed, Status: Post CSR, Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR"}`},
				{`500 Certificate \VED\Policy\TLS/SSL\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR failed with error: Cannot connect to the certificate authority (CA)."}`},
			},
			givenTimeout: 3 * time.Second,
			expectErr:    "unable to retrieve: Unexpected status code on TPP Certificate Retrieval. Status: 500 Certificate \\VED\\Policy\\TLS/SSL\\aexample.com has encountered an error while processing, Status: Post CSR failed with error: Cannot connect to the certificate authority (CA)., Stage: 500.",
		},
		{
			name: "should fail when timeout too small while waiting for the cert",
			mockRetrieve: []mockResp{
				{`202 Certificate \VED\Policy\TLS/SSL\aexample.com being processed, Status: Post CSR, Stage: 500.`,
					`{"Stage": 500, "Status": "Post CSR"}`},
			},
			givenTimeout: 1 * time.Millisecond,
			expectErr:    "Operation timed out. You may try retrieving the certificate later using Pickup ID: \\VED\\Policy\\Test\\bexample.com",
		},
	}
	serverWith := func(t *testing.T, mockRetrieve []mockResp, mockReset mockResp) (_ *httptest.Server, retrieveCount, resetCount *int32) {
		retrieveCount, resetCount = new(int32), new(int32)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/vedsdk/certificates/retrieve":
				index := atomic.AddInt32(retrieveCount, 1) - 1
				if index >= int32(len(mockRetrieve)) {
					t.Fatalf("/retrieve: expected no more than %d calls, but got %d", len(mockRetrieve), index)
				}

				req := certificateRetrieveRequest{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if req.CertificateDN != `\VED\Policy\Test\bexample.com` {
					t.Errorf("/retrieve: expected CertificateDN to be '%s' but got '%s'", `\VED\Policy\Test\bexample.com`, req.CertificateDN)
				}

				writeRespWithCustomStatus(w,
					mockRetrieve[index].status,
					mockRetrieve[index].body,
				)
			case r.URL.Path == "/vedsdk/certificates/reset":
				atomic.AddInt32(resetCount, 1)
				if mockReset == (mockResp{}) {
					t.Errorf("/reset: no call was expected, but got 1 call")
				}
				req := certificateResetRequest{}
				_ = json.NewDecoder(r.Body).Decode(&req)
				if req.CertificateDN != `\VED\Policy\Test\bexample.com` {
					t.Errorf("/vedsdk/certificates/reset: expected CertificateDN to be %s but got %s", `\VED\Policy\Test\bexample.com`, req.CertificateDN)
				}
				if req.Restart != true {
					t.Errorf("/vedsdk/certificates/reset: expected Restart to be true but got false")
				}

				writeRespWithCustomStatus(w, mockReset.status, mockReset.body)
			default:
				t.Fatalf("mock http server: unimplemented path " + r.URL.Path)
			}
		}))
		t.Cleanup(server.Close)
		return server, retrieveCount, resetCount
	}
	for _, tt := range tests {
		tt := tt // Because t.Parallel.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server, retrieveCount, resetCount := serverWith(t, tt.mockRetrieve, tt.mockReset)
			trusted := x509.NewCertPool()
			trusted.AddCert(server.Certificate())

			tpp, err := NewConnector(server.URL, `\VED\Policy\Test`, true, trusted)
			if err != nil {
				t.Fatalf("unexpected err, err: %q, url: %s", err, expectedURL)
			}

			_, err = tpp.RetrieveCertificate(&certificate.Request{PickupID: `\VED\Policy\Test\bexample.com`, Timeout: tt.givenTimeout})
			if atomic.LoadInt32(retrieveCount) != int32(len(tt.mockRetrieve)) {
				t.Errorf("tpp.RetrieveCertificate: expected %d calls to /certificates/retrieve, but got %d", len(tt.mockRetrieve), atomic.LoadInt32(retrieveCount))
			}
			if tt.mockReset == (mockResp{}) && atomic.LoadInt32(resetCount) != 0 {
				t.Errorf("tpp.RetrieveCertificate: expected no call to /certificates/reset, but got %d", atomic.LoadInt32(resetCount))
			}
			if tt.mockReset != (mockResp{}) && atomic.LoadInt32(resetCount) != 1 {
				t.Errorf("tpp.RetrieveCertificate: expected 1 call to /certificates/reset, but got %d", atomic.LoadInt32(resetCount))
			}
			if tt.expectErr != "" {
				if err == nil || err.Error() != tt.expectErr {
					t.Fatalf("tpp.RetrieveCertificate: \nexpected: %q\ngot:      %q", tt.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("tpp.RetrieveCertificate: no error was expected, but got %q", err)
			}
		})
	}
}

// Instead of returning standard statuses such as "400 Bad Request", TPP returns
// HTTP status lines that contain ad-hoc messages, and we need to reproduce this
// same behavior. But Go doesn't support custom HTTP status text, the only way
// to reproduce these HTTP status lines is to hijack the TCP stream and write
// the HTTP/1.1 response manually. Instead of calling w.WriteHeader or w.Write,
// we instead call MockWrite.
//
// Why do we need to care about the HTTP status line, you ask? Because TPP
// sometimes returns the error message in the HTTP status line and not in the
// response body.
//
// Some error messages only appear in the HTTP status line, such as this one:
//
//	HTTP/1.1 403 Failed to issue grant: User is not authorized for the requested scope
//	(no body)
//
// Other error messages only appear in the body but not in the HTTP status line,
// such as:
//
//	HTTP/1.1 401 Unauthorized
//	{"error": "session_error","error_description": "Invalid token format"}
//
// In most cases, the error message appear both in the HTTP status line and in
// the body. For example:
//
//	HTTP/1.1 400 Certificate does not exist.
//	{"Error":"Certificate \\VED\\Policy\\Test\\bexample.com does not exist."}
func writeRespWithCustomStatus(w http.ResponseWriter, status, body string) {
	hj := w.(http.Hijacker)
	conn, bufrw, _ := hj.Hijack()
	defer conn.Close()
	bufrw.WriteString("HTTP/1.1 " + status + "\n\r")
	bufrw.WriteString("Content-Type: application/json\n\r")
	bufrw.WriteString("\n\r")
	bufrw.Write([]byte(body))
	bufrw.Flush()
}

func DoRequestCertificateWithValidHours(t *testing.T, tpp *Connector) {
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

	validHours := 144
	req.ValidityHours = validHours
	req.IssuerHint = "MICROSOFT"

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

func DoRevokeAndDisableCertificate(t *testing.T, tpp *Connector) (req *certificate.Request) {
	config, err := tpp.ReadZoneConfiguration()
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	req = &certificate.Request{}
	req.Subject.CommonName = test.RandCN()
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

	t.Logf("Verifying the Certificate is Disabled")
	guid, err := tpp.configDNToGuid(certDN)
	if err != nil {
		t.Fatalf("%s", err)
	}
	if guid == "" {
		t.Fatalf("Certificate with DN %s doesn't exists", certDN)
	}
	details, err := tpp.searchCertificateDetails(guid)
	if err != nil {
		t.Fatalf("%s", err)
	}

	if details.Disabled {
		t.Logf("The certificate is disabled")
	} else {
		t.Fatalf("The certificate was not disable")
	}

	return req
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

func TestReEnrollRevokedAndDisabledCertificate(t *testing.T) {

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

	req := DoRevokeAndDisableCertificate(t, tpp)

	t.Logf("Trying to re-enable the certificate")
	_, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("The certificate was re-enabled successfully")
}

func TestRevokeAndDisableCertificate(t *testing.T) {

	//cn := test.RandCN()

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

	DoRevokeAndDisableCertificate(t, tpp)
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
	req.CsrOrigin = certificate.ServiceGeneratedCSR
	req.Timeout = time.Second * 10
	err = tpp.GenerateRequest(&endpoint.ZoneConfiguration{}, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	_, err = tpp.RequestCertificate(req)
	if err != nil {
		t.Fatal(err)
	}

	req.FetchPrivateKey = true
	req.KeyPassword = os.Getenv("TPP_PASSWORD")

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
	for _, count := range []int{10, 100, 101, 153, 200, 300} {
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
			t.Errorf("mismatched certificates number: wait %d, got %d for zone %s", count, len(set), ctx.TPPZone)
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

func TestSetPolicy(t *testing.T) {
	policyName := os.Getenv("TPP_PM_ROOT") + "\\" + test.RandTppPolicyName()
	ctx.CloudZone = policyName

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

	ps := test.GetTppPolicySpecification()
	users := []string{"osstestuser"}
	ps.Users = users

	_, err = tpp.SetPolicy(policyName, ps)

	if err != nil {
		t.Fatalf("%s", err)
	}

	ps, err = tpp.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}
	usersEquals := test.StringArraysContainsSameValues(ps.Users, users)
	if !usersEquals {
		t.Fatalf("The users are different, expected %+q but got %+q", users, ps.Users)
	}
}

func TestGetPolicy(t *testing.T) {
	t.Skip() //this is just for development purpose

	policyName := os.Getenv("TPP_POLICY_MANAGEMENT_SAMPLE")

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

	specifiedPS := test.GetTppPolicySpecification()

	ps, err := tpp.GetPolicy(policyName)

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

	//validate cert authority id.
	if specifiedPS.Policy.CertificateAuthority != nil && *(specifiedPS.Policy.CertificateAuthority) != "" {
		if ps.Policy.CertificateAuthority == nil || *(ps.Policy.CertificateAuthority) == "" {
			t.Fatalf("venafi policy doesn't have a certificate authority")
		}
		if *(ps.Policy.CertificateAuthority) != *(specifiedPS.Policy.CertificateAuthority) {
			t.Fatalf("certificate authority value doesn't match, get: %s but expected: %s", *(ps.Policy.CertificateAuthority), *(specifiedPS.Policy.CertificateAuthority))
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

}

func TestSetEmptyPolicy(t *testing.T) {
	policyName := os.Getenv("TPP_PM_ROOT") + "\\" + test.RandTppPolicyName()
	ctx.CloudZone = policyName

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)
	specification := policy.PolicySpecification{}

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	_, err = tpp.SetPolicy(policyName, &specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

}

func TestSetDefaultPolicyValuesAndValidate(t *testing.T) {

	specification := test.GetTppPolicySpecification()

	specification.Policy = nil
	ec := "P384"
	serGenerated := true
	specification.Default.KeyPair.EllipticCurve = &ec
	specification.Default.KeyPair.ServiceGenerated = &serGenerated
	policyName := os.Getenv("TPP_PM_ROOT") + "\\" + test.RandTppPolicyName()
	ctx.CloudZone = policyName

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	_, err = tpp.SetPolicy(policyName, specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//get the created policy
	ps, err := tpp.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if ps.Default == nil {
		t.Fatalf("policy's defaults are nil")
	}
	localDefault := specification.Default
	remoteDefault := ps.Default

	if *(localDefault.AutoInstalled) != *(remoteDefault.AutoInstalled) {
		t.Fatalf("policy's defaults are nil")
	}
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

	/*if *(remoteDefault.KeyPair.EllipticCurve) != *(localDefault.KeyPair.EllipticCurve) {
		t.Fatalf("policy's default ellipticCurve is different expected: %s but get %s", *(localDefault.KeyPair.KeyType), * (remoteDefault.KeyPair.KeyType))
	}*/

	if *(remoteDefault.KeyPair.ServiceGenerated) != *(localDefault.KeyPair.ServiceGenerated) {
		t.Fatalf("policy's default serviceGenerated is different expected: %s but get %s", strconv.FormatBool(*(localDefault.KeyPair.ServiceGenerated)), strconv.FormatBool(*(remoteDefault.KeyPair.ServiceGenerated)))
	}

	if *(remoteDefault.KeyPair.RsaKeySize) != *(localDefault.KeyPair.RsaKeySize) {
		t.Fatalf("policy's default RsaKeySize is different expected: %s but get %s", strconv.Itoa(*(localDefault.KeyPair.RsaKeySize)), strconv.Itoa(*(remoteDefault.KeyPair.RsaKeySize)))
	}

}

func TestSetPolicyValuesAndValidate(t *testing.T) {
	specification := test.GetTppPolicySpecification()

	specification.Default = nil

	policyName := os.Getenv("TPP_PM_ROOT") + "\\" + test.RandTppPolicyName()
	ctx.CloudZone = policyName

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	_, err = tpp.SetPolicy(policyName, specification)

	if err != nil {
		t.Fatalf("%s", err)
	}

	//get the created policy
	ps, err := tpp.GetPolicy(policyName)

	if err != nil {
		t.Fatalf("%s", err)
	}

	if ps.Policy == nil {
		t.Fatalf("policy is nil")
	}
	localPolicy := specification.Policy
	remotePolicy := ps.Policy

	if *(localPolicy.AutoInstalled) != *(remotePolicy.AutoInstalled) {
		t.Fatalf("policy are nil")
	}
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
		t.Fatalf("policy's org are different expected: %+q but get  %+q", localPolicy.Subject.Orgs, remotePolicy.Subject.Orgs)
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

	if *(remotePolicy.KeyPair.ServiceGenerated) != *(localPolicy.KeyPair.ServiceGenerated) {
		t.Fatalf("policy's serviceGenerated is different expected: %s but get %s", strconv.FormatBool(*(localPolicy.KeyPair.ServiceGenerated)), strconv.FormatBool(*(remotePolicy.KeyPair.ServiceGenerated)))
	}

	valid = test.IsArrayIntEqual(remotePolicy.KeyPair.RsaKeySizes, localPolicy.KeyPair.RsaKeySizes)
	if !valid {
		t.Fatalf("policy's RsaKeySizes are different expected:  %+q but get  %+q", localPolicy.KeyPair.RsaKeySizes, remotePolicy.KeyPair.RsaKeySizes)
	}

}

func TestCreateSshCertServiceGeneratedKP(t *testing.T) {

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)

	duration := 4

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	var req = &certificate.SshCertRequest{}

	req.KeyId = test.RandSshKeyId()
	req.ValidityPeriod = fmt.Sprint(duration, "h")
	req.Template = os.Getenv("TPP_SSH_CA")
	req.SourceAddresses = []string{"test.com"}
	req.Timeout = time.Second * 10

	respData, err := tpp.RequestSSHCertificate(req)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	retReq := &certificate.SshCertRequest{
		PickupID:                  respData.DN,
		IncludeCertificateDetails: true,
		Timeout:                   time.Duration(10) * time.Second,
	}

	resp, err := tpp.RetrieveSSHCertificate(retReq)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if resp.PrivateKeyData == "" {
		t.Error("Private key data is empty")
	}

	if resp.PublicKeyData == "" {
		t.Error("Public key data is empty")
	}

	if resp.CertificateData == "" {
		t.Error("Certificate key data is empty")
	}

	validFrom := util.ConvertSecondsToTime(resp.CertificateDetails.ValidFrom)
	validTo := util.ConvertSecondsToTime(resp.CertificateDetails.ValidTo)

	durationFromCert := validTo.Sub(validFrom)

	hours := durationFromCert.Hours()
	intHours := int(hours)
	if intHours != duration {
		t.Errorf("certificate duration is different, expected: %v but got %v", duration, intHours)
	}
}

func TestCreateSshCertLocalGeneratedKP(t *testing.T) {

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)

	duration := 4

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	var req = &certificate.SshCertRequest{}
	req.KeyId = test.RandSshKeyId()

	priv, pub, err := util.GenerateSshKeyPair(3072, "", req.KeyId)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if priv == nil {
		t.Fatalf("generated private key is nil")
	}

	if pub == nil {
		t.Fatalf("generated public key is nil")
	}

	req.ValidityPeriod = fmt.Sprint(duration, "h")
	req.Template = os.Getenv("TPP_SSH_CA")
	req.SourceAddresses = []string{"test.com"}
	req.Timeout = time.Second * 10

	sPubKey := string(pub)

	req.PublicKeyData = sPubKey

	respData, err := tpp.RequestSSHCertificate(req)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	retReq := &certificate.SshCertRequest{
		PickupID:                  respData.DN,
		IncludeCertificateDetails: true,
		Timeout:                   time.Duration(10) * time.Second,
	}

	resp, err := tpp.RetrieveSSHCertificate(retReq)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if resp.PrivateKeyData != "" {
		t.Error("Private key data is not empty")
	}

	if resp.PublicKeyData == "" {
		t.Error("Public key data is empty")
	}

	if resp.PublicKeyData != req.PublicKeyData {
		t.Error("expected public key data is different")
	}

	if resp.CertificateData == "" {
		t.Error("Certificate key data is empty")
	}

	validFrom := util.ConvertSecondsToTime(resp.CertificateDetails.ValidFrom)
	validTo := util.ConvertSecondsToTime(resp.CertificateDetails.ValidTo)

	durationFromCert := validTo.Sub(validFrom)

	hours := durationFromCert.Hours()
	intHours := int(hours)
	if intHours != duration {
		t.Errorf("certificate duration is different, expected: %v but got %v", duration, intHours)
	}
}

func TestCreateSshCertProvidedPubKey(t *testing.T) {
	t.Skip("skipping this test since a fresh generated ssh public key is required")

	var fileContent []byte

	absPath, err := filepath.Abs("../../../test-files/open-source-ssh-cert-test.pub")

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	fileContent, err = ioutil.ReadFile(absPath)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	content := string(fileContent)

	if content == "" {
		t.Fatal("public key is empty")
	}

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)

	duration := 4

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	var req = &certificate.SshCertRequest{}

	req.KeyId = test.RandSshKeyId()
	req.ValidityPeriod = fmt.Sprint(duration, "h")
	req.Template = os.Getenv("TPP_SSH_CA")
	req.PublicKeyData = content
	req.SourceAddresses = []string{"test.com"}

	respData, err := tpp.RequestSSHCertificate(req)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	retReq := &certificate.SshCertRequest{
		PickupID:                  respData.DN,
		IncludeCertificateDetails: true,
		Timeout:                   time.Duration(10) * time.Second,
	}

	resp, err := tpp.RetrieveSSHCertificate(retReq)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if resp.CertificateData == "" {
		t.Error("Certificate key data is empty")
	}

	validFrom := util.ConvertSecondsToTime(resp.CertificateDetails.ValidFrom)
	validTo := util.ConvertSecondsToTime(resp.CertificateDetails.ValidTo)

	durationFromCert := validTo.Sub(validFrom)

	hours := durationFromCert.Hours()
	intHours := int(hours)
	if intHours != duration {
		t.Errorf("certificate duration is different, expected: %v but got %v", duration, intHours)
	}
}

func TestSshGetConfig(t *testing.T) {

	tpp, err := getTestConnector(ctx.TPPurl, ctx.TPPZone)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	tpp.verbose = true

	if tpp.apiKey == "" {
		err = tpp.Authenticate(&endpoint.Authentication{AccessToken: ctx.TPPaccessToken})
		if err != nil {
			t.Fatalf("err is not nil, err: %s", err)
		}
	}

	var req = &certificate.SshCaTemplateRequest{}
	req.Template = os.Getenv("TPP_SSH_CA")

	data, err := tpp.RetrieveSshConfig(req)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if data.CaPublicKey == "" {
		t.Fatalf("CA public key is empty")
	}

	if len(data.Principals) == 0 {
		t.Fatalf("principals are empty  ")
	}

}

func TestGetCertificateMetaData(t *testing.T) {
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

	err = tpp.GenerateRequest(config, req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	t.Logf("getPolicyDN(ctx.TPPZone) = %s", getPolicyDN(ctx.TPPZone))
	dn, err := tpp.RequestCertificate(req)
	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	metaData, err := tpp.RetrieveCertificateMetaData(dn)

	if err != nil {
		t.Fatalf("err is not nil, err: %s", err)
	}

	if metaData == nil {
		t.Fatal("meta data is nil")
	}
}

// TODO: Expand unit tests to cover more cases
func TestSearchValidCertificate(t *testing.T) {
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

	cn := "one.vfidev.com"
	sans := &certificate.Sans{DNS: []string{cn, "two.vfidev.com"}}
	// should find certificate with 2030 expiration date
	zone := "Open Source\\vcert\\Search Certificate"
	// should not find any certificate
	// zone := "Open Source\\vcert\\Search Certificate\\Subpolicy"

	// use time.Duration instead of integer
	day := 24 * time.Hour
	certMinTimeLeft := 3 * day

	certificate, err := tpp.SearchCertificate(zone, cn, sans, certMinTimeLeft)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if certificate == nil {
		t.Fatal("Should have found a certificate")
	}

	fmt.Printf("%v\n", util.GetJsonAsString(*certificate))
}
