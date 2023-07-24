/*
 * Copyright 2023 Venafi, Inc.
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

package firefly

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Connector contains the base data needed to communicate with a Firefly Server
type Connector struct {
	accessToken string
	verbose     bool
	trust       *x509.CertPool
	client      *http.Client
}

func (c *Connector) IsCSRServiceGenerated(req *certificate.Request) (bool, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSshConfig(ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveAvailableSSHTemplates() (response []certificate.SshAvaliableTemplate, err error) {
	panic("operation is not supported yet")
}

// NewConnector creates a new Firefly Connector object used to communicate with Firefly
func NewConnector(verbose bool, trust *x509.CertPool) (*Connector, error) {
	return &Connector{verbose: verbose, trust: trust}, nil
}

func (c *Connector) SetZone(z string) {
	//Given the method vcert.newClient() is generically calling the SetZone() method
	//of the created Connector, then we need to leave this empty because for now the zone is not
	//required
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeFirefly
}

func (c *Connector) Ping() (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	panic("operation is not supported yet")
}

// Authorize Get an OAuth access token
func (c *Connector) Authorize(auth *endpoint.Authentication) (token *oauth2.Token, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", verror.AuthError, err)
		}
	}()

	if auth == nil {
		return nil, fmt.Errorf("failed to authenticate: missing credentials")
	}

	// if it's a password flow grant
	if auth.User != "" && auth.Password != "" {
		config := oauth2.Config{
			ClientID:     auth.ClientId,
			ClientSecret: auth.ClientSecret,
			Scopes:       strings.Split(auth.Scope, " "),
			//RedirectURL:  "http://localhost:9094/oauth2",
			// This points to our Authorization Server
			// if our Client ID and Client Secret are valid
			// it will attempt to authorize our user
			Endpoint: oauth2.Endpoint{
				//AuthURL:  "http://localhost:9096/authorize",
				TokenURL: auth.IdentityProvider.TokenURL,
			},
		}

		return config.PasswordCredentialsToken(context.Background(), auth.User, auth.Password)
	}

	// if it's a client credentials flow grant
	if auth.ClientSecret != "" {

		config := clientcredentials.Config{
			ClientID:     auth.ClientId,
			ClientSecret: auth.ClientSecret,
			TokenURL:     auth.IdentityProvider.TokenURL,
			Scopes:       strings.Split(auth.Scope, " "),
		}
		//if the audience was provided, then it's required to set it to the config.
		if auth.IdentityProvider.Audience != "" {
			audienceList := strings.Split(auth.IdentityProvider.Audience, " ")
			if len(audienceList) > 0 {
				config.EndpointParams = url.Values{
					"audience": audienceList,
				}
			}
		}

		return config.Token(context.Background())
	}

	return
}

func (c *Connector) RetrieveSystemVersion() (string, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RequestCertificate(req *certificate.Request) (requestID string, err error) {
	panic("operation is not supported yet")
}

type ErrCertNotFound struct {
	error
}

func (e *ErrCertNotFound) Error() string {
	return e.error.Error()
}

func (e *ErrCertNotFound) Unwrap() error {
	return e.error
}

func (c *Connector) ResetCertificate(req *certificate.Request, restart bool) (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {
	panic("operation is not supported yet")
}

func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) ReadPolicyConfiguration() (policy *endpoint.Policy, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SearchCertificates(req *certificate.SearchRequest) (*certificate.CertSearchResponse, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SearchCertificate(zone string, cn string, sans *certificate.Sans, certMinTimeLeft time.Duration) (certificateInfo *certificate.CertificateInfo, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Connector) WriteLog(logReq *endpoint.LogRequest) error {
	panic("operation is not supported yet")
}

func (c *Connector) ListCertificates(filter endpoint.Filter) ([]certificate.CertificateInfo, error) {
	panic("operation is not supported yet")
}

func (c *Connector) GetZonesByParent(parent string) ([]string, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RequestSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveCertificateMetaData(dn string) (*certificate.CertificateMetaData, error) {
	panic("operation is not supported yet")
}
