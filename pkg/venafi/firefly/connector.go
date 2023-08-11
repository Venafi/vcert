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

	"github.com/sosodev/duration"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

// Connector contains the base data needed to communicate with a Firefly Server
type Connector struct {
	baseURL     string
	accessToken string
	verbose     bool
	trust       *x509.CertPool
	client      *http.Client
	zone        string // holds the policyName
}

func (c *Connector) IsCSRServiceGenerated(_ *certificate.Request) (bool, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSshConfig(_ *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveAvailableSSHTemplates() (response []certificate.SshAvaliableTemplate, err error) {
	panic("operation is not supported yet")
}

// NewConnector creates a new Firefly Connector object used to communicate with Firefly
func NewConnector(url string, zone string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	return &Connector{baseURL: url, zone: zone, verbose: verbose, trust: trust}, nil
}

func (c *Connector) SetZone(zone string) {
	//for now the zone refers to the policyName
	c.zone = zone
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeFirefly
}

func (c *Connector) Ping() (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) Authenticate(_ *endpoint.Authentication) (err error) {
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

// RequestCertificate submits the CSR to the Venafi Firefly API for processing
func (c *Connector) RequestCertificate(_ *certificate.Request) (requestID string, err error) {
	panic("operation is not supported yet")
}

// SynchronousRequestCertificate It's not supported yet in VaaS
func (c *Connector) SynchronousRequestCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {

	//creating the request object
	certReq := c.getCertificateRequest(req)
	if err != nil {
		return nil, err
	}

	statusCode, status, body, err := c.request("POST", c.getCertificateRequestUrl(req), certReq)

	if err != nil {
		return nil, err
	}
	//parsing the result
	cr, err := parseCertificateRequestResult(statusCode, status, body)
	if err != nil {
		return nil, err
	}
	//converting to PEMCollection
	certificates, err = certificate.PEMCollectionFromBytes([]byte(cr.CertificateChain), req.ChainOption)
	if err != nil {
		return nil, err
	}
	certificates.PrivateKey = cr.PrivateKey
	return certificates, nil
}

func (c *Connector) getCertificateRequest(req *certificate.Request) *certificateRequest {
	fireflyCertRequest := &certificateRequest{}

	if req.CsrOrigin == certificate.UserProvidedCSR {
		fireflyCertRequest.CSR = string(req.GetCSR())
	} else { // it's considered as a ServiceGeneratedCSR
		//getting the subject
		subject := Subject{
			CommonName: req.Subject.CommonName,
		}

		if len(req.Subject.Organization) > 0 {
			subject.Organization = req.Subject.Organization[0]
		}

		if len(req.Subject.OrganizationalUnit) > 0 {
			subject.OrgUnits = req.Subject.OrganizationalUnit
		}

		if len(req.Subject.Locality) > 0 {
			subject.Locality = req.Subject.Locality[0]
		}

		if len(req.Subject.Province) > 0 {
			subject.State = req.Subject.Province[0]
		}

		if len(req.Subject.Country) > 0 {
			subject.Country = req.Subject.Country[0]
		}

		fireflyCertRequest.Subject = subject

		//getting the altnames
		if len(req.DNSNames) > 0 || len(req.IPAddresses) > 0 || len(req.EmailAddresses) > 0 || len(req.URIs) > 0 {
			altNames := &AlternativeNames{}
			if len(req.DNSNames) > 0 {
				altNames.DnsNames = req.DNSNames
			}

			if len(req.IPAddresses) > 0 {
				sIPAddresses := make([]string, 0)
				for _, address := range req.IPAddresses {
					sIPAddresses = append(sIPAddresses, address.String())
				}

				altNames.IpAddresses = sIPAddresses
			}

			if len(req.EmailAddresses) > 0 {
				altNames.EmailAddresses = req.EmailAddresses
			}

			if len(req.URIs) > 0 {
				sUris := make([]string, 0)
				for _, uri := range req.URIs {
					sUris = append(sUris, uri.String())
				}
				altNames.Uris = sUris
			}

			fireflyCertRequest.AlternativeName = altNames
		}
	}

	if req.ValidityPeriod != "" {
		fireflyCertRequest.ValidityPeriod = &req.ValidityPeriod
	} else {
		if req.ValidityDuration != nil { //if the validityDuration was set then it will convert to ISO 8601
			validityPeriod := duration.Format(*req.ValidityDuration)
			fireflyCertRequest.ValidityPeriod = &validityPeriod
		}
	}

	fireflyCertRequest.PolicyName = c.zone

	//getting the keyAlgorithm
	keyAlgorithm := ""
	switch req.KeyType {
	case certificate.KeyTypeRSA:
		keyAlgorithm = fmt.Sprintf("RSA_%d", req.KeyLength)

	case certificate.KeyTypeECDSA, certificate.KeyTypeED25519:
		keyAlgorithm = fmt.Sprintf("EC_%s", req.KeyCurve.String())
	}
	fireflyCertRequest.KeyAlgorithm = keyAlgorithm

	return fireflyCertRequest
}

func (c *Connector) getCertificateRequestUrl(req *certificate.Request) urlResource {
	if req.CsrOrigin == certificate.UserProvidedCSR {
		return urlResourceCertificateRequestCSR
	}

	return urlResourceCertificateRequest
}

// SupportSynchronousRequestCertificate returns if the connector support synchronous calls to request a certificate.
func (c *Connector) SupportSynchronousRequestCertificate() bool {
	return true
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

func (c *Connector) ResetCertificate(_ *certificate.Request, restart bool) (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) GetPolicy(_ string) (*policy.PolicySpecification, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SetPolicy(_ string, _ *policy.PolicySpecification) (string, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveCertificate(_ *certificate.Request) (certificates *certificate.PEMCollection, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RenewCertificate(_ *certificate.RenewalRequest) (requestID string, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RevokeCertificate(_ *certificate.RevocationRequest) (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) ReadPolicyConfiguration() (policy *endpoint.Policy, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	return nil, nil
}

func (c *Connector) ImportCertificate(_ *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SearchCertificates(_ *certificate.SearchRequest) (*certificate.CertSearchResponse, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SearchCertificate(_ string, _ string, _ *certificate.Sans, _ time.Duration) (certificateInfo *certificate.CertificateInfo, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Connector) WriteLog(_ *endpoint.LogRequest) error {
	panic("operation is not supported yet")
}

func (c *Connector) ListCertificates(_ endpoint.Filter) ([]certificate.CertificateInfo, error) {
	panic("operation is not supported yet")
}

func (c *Connector) GetZonesByParent(_ string) ([]string, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RequestSSHCertificate(_ *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSSHCertificate(_ *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveCertificateMetaData(_ string) (*certificate.CertificateMetaData, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetireCertificate(_ *certificate.RetireRequest) error {
	panic("operation is not supported yet")
}
