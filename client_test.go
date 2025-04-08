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

package vcert

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-http-utils/headers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
)

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func print(a interface{}) {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	fmt.Println(string(b))
}

func TestNewClient(t *testing.T) {
	var haltIf = func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	var cfg = &Config{
		ConnectorType: endpoint.ConnectorTypeFake,
	}

	c, err := NewClient(cfg)
	haltIf(err)

	req := &certificate.Request{
		Subject: pkix.Name{
			CommonName:   "client.venafi.example.com",
			Organization: []string{"Venafi.com"}, OrganizationalUnit: []string{"Integration Team"}},
		DNSNames: []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
	}

	err = c.GenerateRequest(nil, req)
	haltIf(err)
	print(req)

	id, err := c.RequestCertificate(req)
	haltIf(err)
	print(id)

	req.Timeout = 180 * time.Second
	certs, err := c.RetrieveCertificate(req)
	haltIf(err)
	print(certs)
}

func TestNewClientWithFileConfig(t *testing.T) {
	var haltIf = func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}

	tmpfile, err := ioutil.TempFile("", "")

	if err != nil {
		t.Fatal(err)
	}
	defer func(name string) {
		err := os.Remove(name)
		if err != nil {
			t.Fatal(err)
		}
	}(tmpfile.Name())

	err = ioutil.WriteFile(tmpfile.Name(), []byte("test_mode = true"), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfigFromFile(tmpfile.Name(), "")
	if err != nil {
		t.Fatal(err)
	}

	c, err := NewClient(&cfg)
	haltIf(err)

	req := &certificate.Request{
		Subject: pkix.Name{
			CommonName:   "client.venafi.example.com",
			Organization: []string{"Venafi.com"}, OrganizationalUnit: []string{"Integration Team"}},
		DNSNames: []string{"www.client.venafi.example.com", "ww1.client.venafi.example.com"},
	}

	err = c.GenerateRequest(nil, req)
	haltIf(err)
	print(req)

	id, err := c.RequestCertificate(req)
	haltIf(err)
	print(id)

	req.Timeout = 180 * time.Second
	certs, err := c.RetrieveCertificate(req)
	haltIf(err)
	print(certs)
}

// userAgentChecker can be used as an http.Client.Transport (RoundTripper) to
// check that the User-Agent header is being consistently added to HTTP requests.
type userAgentChecker struct {
	t             *testing.T
	config        Config
	expectedError error
}

// newUserAgentChecker creates a userAgentChecker configured for the UserAgent
// in the supplied Config.
//
// It sets up the Client field of the supplied Config so that any HTTP requests
// will be checked for the expected User-Agent value among the HTTP headers.
// The in-memory HTTP client used to verify the User-Agent headers will always
// return a sentinel error.
// Use `RequireRoundTripError` to check that the expected sentinel error is
// returned by any method of the connector which is expected to make HTTP
// requests.
// The connector should be generated using `vcert.Config.NewClient` or `vcert.NewClient(Config)“
func newUserAgentChecker(t *testing.T, config *Config) *userAgentChecker {
	uac := &userAgentChecker{
		t:             t,
		config:        *config,
		expectedError: errors.New("simulated-error"),
	}
	config.Client = &http.Client{
		Transport: uac,
	}
	return uac
}

// RoundTrip implements http.RoundTripper.RoundTrip.
//
// It verifies the User-Agent header and dumps the request content as test log
// messages, to make it easier to inspect the HTTP request headers.
// It always returns a simulated error and never returns an http.Response.
func (o *userAgentChecker) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBytes, err := httputil.DumpRequest(req, true)
	require.NoError(o.t, err)
	o.t.Log(string(reqBytes))

	assert.Len(o.t, req.Header.Values(headers.UserAgent), 1,
		"There must always be one User-Agent header set, "+
			"to avoid the Go http DefaultClient setting the User-Agent header to Go-HTTP-1.1 by default")

	actualUserAgent := req.Header.Get(headers.UserAgent)

	if o.config.UserAgent == nil {
		assert.Equal(o.t, util.DefaultUserAgent, actualUserAgent,
			"User-Agent header should be vcert/v5 when the config.UserAgent field is omitted")
	} else {
		assert.Equal(o.t, *o.config.UserAgent, actualUserAgent,
			"User-Agent header should match config.UserAgent when the field is set")
	}

	return nil, o.expectedError
}

// RequireRoundTripError is used to check the error returned by any function
// that has been instrumented with the NewHTTPClient (above). The instrumented
// function is therefore expected to generate HTTP requests and where it does,
// it is expected to return or wrap the error that is always returned by the
// RoundTripper of this test helper.
func (o *userAgentChecker) RequireRoundTripError(err error) {
	require.ErrorContains(o.t, err, o.expectedError.Error(),
		"The user supplied HTTP client (with simulated-error RoundTripper) should always be used, "+
			"so the simulated-error should always be returned here. "+
			"If not, it indicates one of two programming errors: "+
			"1. the function is calling API endpoints with the wrong HTTP client, or "+
			"2. the function is ignoring or hiding the error returned in the HTTP response.")
}

// TestNewClient_UserAgent checks that all connectors are consistent in the way
// they set the User-Agent header.
//
// The desired behavior is that a User-Agent header is always included the
// requests.
// If the Config.UserAgent field is nil, the default UserAgent value is used.
// Else, the supplied UserAgent string is used, even when empty.
func TestNewClient_UserAgent(t *testing.T) {
	// These base connector configs will be tested
	connectorConfigs := []Config{
		{
			ConnectorType: endpoint.ConnectorTypeCloud,
		},
		{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       "https://tpp.example.local",
		},
		{
			ConnectorType: endpoint.ConnectorTypeFirefly,
			BaseUrl:       "https://firefly.example.local",
		},
	}

	// These methods will be called on every connector.
	connectorMethods := []struct {
		name string
		f    func(c endpoint.Connector, args ...any) error
	}{
		{
			name: "Authenticate",
			f: func(c endpoint.Connector, args ...any) error {
				credentials, ok := args[0].(*endpoint.Authentication)
				if !ok {
					return fmt.Errorf("unexpected args: %T", args[0])
				}
				return c.Authenticate(credentials)
			},
		},
		{
			name: "Ping",
			f: func(c endpoint.Connector, _ ...any) error {
				return c.Ping()
			},
		},
		{
			name: "ListCertificates",
			f: func(c endpoint.Connector, args ...any) error {
				filter, ok := args[0].(endpoint.Filter)
				if !ok {
					return fmt.Errorf("unexpected args: %T", args[0])
				}
				_, err := c.ListCertificates(filter)
				return err
			},
		},
		{
			name: "RequestCertificates",
			f: func(c endpoint.Connector, args ...any) error {
				request, ok := args[0].(*certificate.Request)
				if !ok {
					return fmt.Errorf("unexpected args: %T", args[0])
				}
				_, err := c.RequestCertificate(request)
				return err
			},
		},
		{
			name: "SynchronousRequestCertificate",
			f: func(c endpoint.Connector, args ...any) error {
				request, ok := args[0].(*certificate.Request)
				if !ok {
					return fmt.Errorf("unexpected args: %T", args[0])
				}
				_, err := c.SynchronousRequestCertificate(request)
				return err
			},
		},
	}

	// Methods will be called with all the arguments where test matches `test`.
	//
	// If the connector + method only need so be tested with one combination of
	// argument, then the name can be omitted.
	// If there are no arguments, each connector + method be called once without
	// any arguments
	type methodArguments struct {
		name string
		test string
		args []any
	}
	args := []methodArguments{
		{
			test: endpoint.ConnectorTypeCloud.String() + ":Authenticate",
			name: "with-api-key",
			args: []any{
				&endpoint.Authentication{
					APIKey: "fake-key",
				},
			},
		},
		{
			test: endpoint.ConnectorTypeCloud.String() + ":Authenticate",
			name: "with-service-account",
			args: []any{
				&endpoint.Authentication{
					ExternalJWT: "fake-external-idp-jwt",
					TokenURL:    "https://fake.token.url.com/token",
				},
			},
		},
		{
			test: endpoint.ConnectorTypeTPP.String() + ":Authenticate",
			args: []any{
				&endpoint.Authentication{
					User:     "fake-user",
					Password: "fake-password",
				},
			},
		},
		{
			test: endpoint.ConnectorTypeFirefly.String() + ":Authenticate",
			args: []any{
				&endpoint.Authentication{
					IdentityProvider: &endpoint.OAuthProvider{
						DeviceURL: "https://device.oauth.example.local",
					},
				},
			},
		},
		{
			test: ":ListCertificates",
			args: []any{
				endpoint.Filter{},
			},
		},
		{
			test: ":RequestCertificates",
			args: []any{
				&certificate.Request{},
			},
		},
		{
			test: ":SynchronousRequestCertificate",
			args: []any{
				&certificate.Request{},
			},
		},
	}

	// These User-Agent strings will be tested with every method of every
	// connector.
	userAgents := []struct {
		name  string
		value *string
	}{
		{
			name:  "override-user-agent",
			value: ptr.To("fake-user-agent/v9.9.9"),
		},
		{
			name:  "omit-user-agent",
			value: ptr.To(""),
		},
		{
			name:  "default-user-agent",
			value: nil,
		},
	}

	// These tests will be skipped because the connector does not yet implement
	// the method.
	skips := []string{
		endpoint.ConnectorTypeCloud.String() + ":Ping",
		endpoint.ConnectorTypeCloud.String() + ":SynchronousRequestCertificate",

		endpoint.ConnectorTypeTPP.String() + ":SynchronousRequestCertificate",

		endpoint.ConnectorTypeFirefly.String() + ":Ping",
		endpoint.ConnectorTypeFirefly.String() + ":ListCertificates",
		endpoint.ConnectorTypeFirefly.String() + ":RequestCertificates",
	}

	for _, config := range connectorConfigs {
		for _, method := range connectorMethods {
			name := fmt.Sprintf("%s:%s", config.ConnectorType.String(), method.name)
			var matchingArgs []methodArguments
			for _, arg := range args {
				re := regexp.MustCompile(arg.test)
				if re.MatchString(name) {
					matchingArgs = append(matchingArgs, arg)
				}
			}
			if len(matchingArgs) == 0 {
				matchingArgs = []methodArguments{{}}
			}
			for _, arg := range matchingArgs {
				name := name
				if arg.name != "" {
					name = name + ":" + arg.name
				}
				for _, userAgent := range userAgents {
					name := name + ":" + userAgent.name
					t.Run(
						name,
						func(t *testing.T) {
							for _, skipPrefix := range skips {
								if strings.HasPrefix(name, skipPrefix) {
									t.Skip("not supported")
								}
							}

							config.UserAgent = userAgent.value

							// The TPP and Cloud connectors both require a zone to be set
							config.Zone = "fake-zone"

							uaChecker := newUserAgentChecker(t, &config)

							c, err := NewClient(&config, false)
							require.NoError(t, err,
								"NewClient with auth argument set to false should have no side effects "+
									"and should always succeed.")

							// The VaaS connector requires this because before even
							// attempting to send requests to resource endpoints it
							// checks the connector.accessToken attribute, and the
							// only way to set that is to call Authenticate with an
							// AccessToken credential.
							if c.GetType() == endpoint.ConnectorTypeCloud {
								credentials := &endpoint.Authentication{
									AccessToken: "fake-access-token",
								}
								err = c.Authenticate(credentials)
								require.NoError(t, err,
									"For the VaaS connector Authenticate with AccessToken simply sets an attribute; "+
										"it does not trigger any HTTP requests, so there should never be an error.")
							}

							err = method.f(c, arg.args...)
							uaChecker.RequireRoundTripError(err)
						},
					)
				}
			}
		}
	}
}
