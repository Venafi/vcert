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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sosodev/duration"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/venafi"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

var (
	fieldPlatform = zap.String("platform", venafi.Firefly.String())
)

// Connector contains the base data needed to communicate with a Firefly Server
type Connector struct {
	baseURL     string
	accessToken string
	verbose     bool
	trust       *x509.CertPool
	client      *http.Client
	zone        string // holds the policyName
	userAgent   string
}

// NewConnector creates a new Firefly Connector object used to communicate with Firefly
func NewConnector(url string, zone string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	if url != "" {
		var err error
		url, err = normalizeURL(url)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to normalize URL: %v", verror.UserDataError, err)
		}
	}
	return &Connector{baseURL: url, zone: zone, verbose: verbose, trust: trust, userAgent: util.DefaultUserAgent}, nil
}

// normalizeURL normalizes the base URL used to communicate with Firefly
func normalizeURL(url string) (normalizedURL string, err error) {
	normalizedURL = util.NormalizeUrl(url)
	return normalizedURL, err
}

func (c *Connector) SetZone(zone string) {
	//for now the zone refers to the policyName
	c.zone = zone
}

func (c *Connector) SetUserAgent(userAgent string) {
	c.userAgent = userAgent
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeFirefly
}

// Authenticate authenticates the connector to the Firefly server.
// In the future, this method will send a request to the Firefly server to validate the authentication.
func (c *Connector) Authenticate(auth *endpoint.Authentication) error {
	if err := c.SetAuthentication(auth); err != nil {
		return err
	}

	// TODO: use the access token to send a request and validate the authentication.

	return nil
}

// SetAuthentication sets the authentication details to connect to the Firefly server
func (c *Connector) SetAuthentication(auth *endpoint.Authentication) error {
	if auth == nil {
		msg := "failed to authenticate: no credentials provided"
		zap.L().Error(msg, fieldPlatform)
		return errors.New(msg)
	}

	if auth.AccessToken == "" {
		zap.L().Info("no access token provided. Authorization needed", fieldPlatform)
		var token *oauth2.Token
		token, err := c.Authorize(auth)
		if err != nil {
			return err
		}
		auth.AccessToken = token.AccessToken
	}

	zap.L().Info("successfully authenticated", fieldPlatform)
	//setting the accessToken to the connector
	c.accessToken = auth.AccessToken
	return nil
}

// Authorize Get an OAuth access token
func (c *Connector) Authorize(auth *endpoint.Authentication) (token *oauth2.Token, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", verror.AuthError, err)
		}
	}()

	zap.L().Info("authorizing to OAuth2 server", fieldPlatform)

	if auth == nil {
		msg := "failed to authenticate: missing credentials"
		zap.L().Error(msg, fieldPlatform)
		return nil, errors.New(msg)
	}

	successMsg := "successfully authorized to OAuth2 server"
	failureMsg := "authorization flow failed"

	// if it's a client credentials flow grant
	if auth.ClientSecret != "" && auth.IdentityProvider.DeviceURL == "" {
		zap.L().Info("authorizing using credentials flow", fieldPlatform)

		config := clientcredentials.Config{
			ClientID:     auth.ClientId,
			ClientSecret: auth.ClientSecret,
			TokenURL:     auth.IdentityProvider.TokenURL,
			Scopes:       strings.Split(auth.Scope, scopesSeparator),
		}
		//if the audience was provided, then it's required to set it to the config.
		if auth.IdentityProvider.Audience != "" {
			config.EndpointParams = url.Values{
				"audience": []string{auth.IdentityProvider.Audience},
			}
		}

		token, err = config.Token(context.Background())
		if err != nil {
			zap.L().Error(failureMsg, fieldPlatform, zap.Error(err))
			return token, err
		}

		zap.L().Info(successMsg, fieldPlatform)
		return
	}

	// if it's a password flow grant
	if auth.User != "" && auth.Password != "" {
		zap.L().Info("authorizing using password flow", fieldPlatform)

		config := oauth2.Config{
			ClientID:     auth.ClientId,
			ClientSecret: auth.ClientSecret,
			Scopes:       strings.Split(auth.Scope, scopesSeparator),
			//RedirectURL:  "http://localhost:9094/oauth2",
			// This points to our Authorization Server
			// if our Client ID and Client Secret are valid
			// it will attempt to authorize our user
			Endpoint: oauth2.Endpoint{
				//AuthURL:  "http://localhost:9096/authorize",
				TokenURL: auth.IdentityProvider.TokenURL,
			},
		}

		token, err = config.PasswordCredentialsToken(context.Background(), auth.User, auth.Password)
		if err != nil {
			zap.L().Error(failureMsg, fieldPlatform, zap.Error(err))
			return token, err
		}

		zap.L().Info(successMsg, fieldPlatform)
		return
	}

	// if it's a device flow grant
	if auth.IdentityProvider.DeviceURL != "" {
		zap.L().Info("authorizing using device flow", fieldPlatform)

		token, err = c.getDeviceAccessToken(auth)
		if err != nil {
			zap.L().Error(failureMsg, fieldPlatform, zap.Error(err))
			return token, err
		}

		zap.L().Info(successMsg, fieldPlatform)
		return
	}

	errMsg := "authorization failed: cannot determine the authorization flow required for the credentials provided"
	zap.L().Error(errMsg, fieldPlatform)
	return token, errors.New(errMsg)
}

// SynchronousRequestCertificate It's not supported yet in VaaS
func (c *Connector) SynchronousRequestCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {

	zap.L().Info("requesting certificate", zap.String("cn", req.Subject.CommonName), fieldPlatform)
	//creating the request object
	certReq, err := c.getCertificateRequest(req)
	if err != nil {
		zap.L().Error("HTTP request failed", fieldPlatform, zap.Error(err))
		return nil, err
	}

	zap.L().Info("sending HTTP request", fieldPlatform)
	statusCode, status, body, err := c.request("POST", c.getCertificateRequestUrl(req), certReq)
	if err != nil {
		zap.L().Error("HTTP request failed", fieldPlatform, zap.Error(err))
		return nil, err
	}

	//parsing the result
	cr, err := parseCertificateRequestResult(statusCode, status, body)
	if err != nil {
		zap.L().Error("failed to request a certificate", fieldPlatform, zap.Error(err))
		return nil, err
	}

	//converting to PEMCollection
	certificates, err = certificate.PEMCollectionFromBytes([]byte(cr.CertificateChain), req.ChainOption)
	if err != nil {
		zap.L().Error("failed to create pem collection", fieldPlatform, zap.Error(err))
		return nil, err
	}

	certificates.PrivateKey = cr.PrivateKey
	zap.L().Info("successfully requested certificate", fieldPlatform)
	return certificates, nil
}

func (c *Connector) getCertificateRequest(req *certificate.Request) (*certificateRequest, error) {
	zap.L().Info("building certificate request", fieldPlatform)
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
		keySize, err := GetRSASize(req.KeyLength)
		if err != nil {
			return nil, err
		}
		keyAlgorithm = fmt.Sprintf("RSA_%d", keySize)
	case certificate.KeyTypeECDSA, certificate.KeyTypeED25519:
		keyCurve := req.KeyCurve
		if keyCurve == certificate.EllipticCurveNotSet {
			keyCurve = certificate.EllipticCurveDefault
		}
		keyAlgorithm = fmt.Sprintf("EC_%s", keyCurve.String())
	}
	fireflyCertRequest.KeyAlgorithm = keyAlgorithm

	zap.L().Info("successfully built certificate request", fieldPlatform)
	return fireflyCertRequest, nil
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

func (c *Connector) Ping() (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSystemVersion() (string, error) {
	panic("operation is not supported yet")
}

// RequestCertificate submits the CSR to the Venafi Firefly API for processing
func (c *Connector) RequestCertificate(_ *certificate.Request) (requestID string, err error) {
	panic("operation is not supported yet")
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

func (c *Connector) ResetCertificate(_ *certificate.Request, _ bool) (err error) {
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

func (c *Connector) ProvisionCertificate(_ *domain.ProvisioningRequest, _ *domain.ProvisioningOptions) (*domain.ProvisioningMetadata, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveCertificateMetaData(_ string) (*certificate.CertificateMetaData, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetireCertificate(_ *certificate.RetireRequest) error {
	panic("operation is not supported yet")
}
