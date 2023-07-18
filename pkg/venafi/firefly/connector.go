/*
 * Copyright 2018-2022 Venafi, Inc.
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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Connector contains the base data needed to communicate with a Firefly Server
type Connector struct {
	baseURL     string
	apiKey      string
	accessToken string
	verbose     bool
	Identity    identity
	trust       *x509.CertPool
	zone        string
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

// NewConnector creates a new TPP Connector object used to communicate with TPP
func NewConnector(url string, zone string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	c := Connector{verbose: verbose, trust: trust, zone: zone}
	var err error
	c.baseURL, err = normalizeURL(url)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to normalize URL: %v", verror.UserDataError, err)
	}
	return &c, nil
}

// normalizeURL normalizes the base URL used to communicate with TPP
func normalizeURL(url string) (normalizedURL string, err error) {
	var baseUrlRegex = regexp.MustCompile(`^https://[a-z\d]+[-a-z\d.]+[a-z\d][:\d]*/$`)
	modified := strings.ToLower(url)
	if strings.HasPrefix(modified, "http://") {
		modified = "https://" + modified[7:]
	} else if !strings.HasPrefix(modified, "https://") {
		modified = "https://" + modified
	}
	if !strings.HasSuffix(modified, "/") {
		modified = modified + "/"
	}

	modified = strings.TrimSuffix(modified, "vedsdk/")

	if loc := baseUrlRegex.FindStringIndex(modified); loc == nil {
		return "", fmt.Errorf("The specified TPP URL is invalid. %s\nExpected TPP URL format 'https://tpp.company.com/vedsdk/'", url)
	}

	return modified, nil
}

func (c *Connector) SetZone(z string) {
	c.zone = z
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeTPP
}

// Ping attempts to connect to the TPP Server WebSDK API and returns an error if it cannot
func (c *Connector) Ping() (err error) {

	//Extended timeout to allow the server to wake up
	c.getHTTPClient().Timeout = time.Second * 90
	statusCode, status, _, err := c.request("GET", "vedsdk/", nil)
	if err != nil {
		return
	}
	if statusCode != http.StatusOK {
		err = fmt.Errorf(status)
	}
	return
}

// Authenticate authenticates the user to the TPP
func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", verror.AuthError, err)
		}
	}()

	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.ClientId == "" {
		auth.ClientId = defaultClientID
	}

	if auth.User != "" && auth.Password != "" {
		data := authorizeResquest{Username: auth.User, Password: auth.Password}
		result, err := processAuthData(c, urlResourceAuthorize, data)
		if err != nil {
			return err
		}

		resp := result.(authorizeResponse)
		c.apiKey = resp.APIKey

		if c.client != nil {
			c.Identity, err = c.retrieveSelfIdentity()
			if err != nil {
				return err
			}
		}
		return nil

	} else if auth.RefreshToken != "" {
		data := oauthRefreshAccessTokenRequest{Client_id: auth.ClientId, Refresh_token: auth.RefreshToken}
		result, err := processAuthData(c, urlResourceRefreshAccessToken, data)
		if err != nil {
			return err
		}

		resp := result.(OauthRefreshAccessTokenResponse)
		c.accessToken = resp.Access_token
		auth.RefreshToken = resp.Refresh_token
		if c.client != nil {
			c.Identity, err = c.retrieveSelfIdentity()
			if err != nil {
				return err
			}
		}
		return nil

	} else if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken

		if c.client != nil {
			c.Identity, err = c.retrieveSelfIdentity()
			if err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("failed to authenticate: can't determine valid credentials set")
}

// Authorize Get OAuth refresh and access token
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
			Scopes:       []string{"all"},
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
		}

		return config.Token(context.Background())
	}

	return
}

// GetRefreshToken Get OAuth refresh and access token
func (c *Connector) GetRefreshToken(auth *endpoint.Authentication) (resp OauthTokenResponse, err error) {
	panic("operation is not supported yet")
}

// RefreshAccessToken Refresh OAuth access token
func (c *Connector) RefreshAccessToken(auth *endpoint.Authentication) (resp OauthRefreshAccessTokenResponse, err error) {
	panic("operation is not supported yet")
}

// VerifyAccessToken - call to check whether token is valid and, if so, return its properties
func (c *Connector) VerifyAccessToken(auth *endpoint.Authentication) (resp OauthVerifyTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken
		statusCode, statusText, body, err := c.request("GET", urlResource(urlResourceAuthorizeVerify), nil)
		if err != nil {
			return resp, err
		}

		if statusCode == http.StatusOK {
			var result = &OauthVerifyTokenResponse{}
			err = json.Unmarshal(body, result)
			if err != nil {
				return resp, fmt.Errorf("failed to parse verify token response: %s, body: %s", err, body)
			}
			return *result, nil
		}
		return resp, fmt.Errorf("failed to verify token. Message: %s", statusText)
	}

	return resp, fmt.Errorf("failed to authenticate: missing access token")
}

// RevokeAccessToken - call to revoke token so that it can never be used again
func (c *Connector) RevokeAccessToken(auth *endpoint.Authentication) (err error) {
	panic("operation is not supported yet")
}

func processAuthData(c *Connector, url urlResource, data interface{}) (resp interface{}, err error) {

	//isReachable, err := c.isAuthServerReachable()
	//if err != nil {
	//	return nil, err
	//}
	//if !isReachable {
	//	return nil, fmt.Errorf("authentication server is not reachable: %s", c.baseURL)
	//}

	statusCode, status, body, err := c.request("POST", url, data)
	if err != nil {
		return resp, err
	}

	var getRefresh OauthTokenResponse
	var refreshAccess OauthRefreshAccessTokenResponse
	var authorize authorizeResponse

	if statusCode == http.StatusOK {
		switch data.(type) {
		case OauthAuthorizeRequest:
			err = json.Unmarshal(body, &getRefresh)
			if err != nil {
				return resp, err
			}
			resp = getRefresh
		case oauthRefreshAccessTokenRequest:
			err = json.Unmarshal(body, &refreshAccess)
			if err != nil {
				return resp, err
			}
			resp = refreshAccess
		case authorizeResquest:
			err = json.Unmarshal(body, &authorize)
			if err != nil {
				return resp, err
			}
			resp = authorize
		case oauthCertificateTokenRequest:
			err = json.Unmarshal(body, &getRefresh)
			if err != nil {
				return resp, err
			}
			resp = getRefresh
		default:
			return resp, fmt.Errorf("can not determine data type")
		}
	} else {
		return resp, fmt.Errorf("unexpected status code on TPP Authorize. Status: %s", status)
	}

	return resp, nil
}

func wrapAltNames(req *certificate.Request) (items []sanItem) {
	for _, name := range req.EmailAddresses {
		items = append(items, sanItem{1, name})
	}
	for _, name := range req.DNSNames {
		items = append(items, sanItem{2, name})
	}
	for _, name := range req.IPAddresses {
		items = append(items, sanItem{7, name.String()})
	}
	for _, name := range req.URIs {
		items = append(items, sanItem{6, name.String()})
	}
	for _, name := range req.UPNs {
		items = append(items, sanItem{0, name})
	}
	return items
}

func prepareLegacyMetadata(c *Connector, metaItems []customField, dn string) ([]guidData, error) {
	metadataItems, err := c.requestAllMetadataItems(dn)
	if nil != err {
		return nil, err
	}
	customFieldsGUIDMap := make(map[string]string)
	for _, item := range metadataItems {
		customFieldsGUIDMap[item.Label] = item.Guid
	}

	var requestGUIDData []guidData
	for _, item := range metaItems {
		guid, prs := customFieldsGUIDMap[item.Name]
		if prs {
			requestGUIDData = append(requestGUIDData, guidData{guid, item.Values})
		}
	}
	return requestGUIDData, nil
}

// requestAllMetadataItems returns all possible metadata items for a DN
func (c *Connector) requestAllMetadataItems(dn string) ([]metadataItem, error) {
	statusCode, status, body, err := c.request("POST", urlResourceAllMetadataGet, metadataGetItemsRequest{dn})
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Unexpected http status code while fetching metadata items. %d-%s", statusCode, status)
	}

	var response metadataGetItemsResponse
	err = json.Unmarshal(body, &response)
	return response.Items, err
}

// requestMetadataItems returns metadata items for a DN that have a value stored
func (c *Connector) requestMetadataItems(dn string) ([]metadataKeyValueSet, error) {
	statusCode, status, body, err := c.request("POST", urlResourceMetadataGet, metadataGetItemsRequest{dn})
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("Unexpected http status code while fetching certificate metadata items. %d-%s", statusCode, status)
	}
	var response metadataGetResponse
	err = json.Unmarshal(body, &response)
	return response.Data, err
}

// Retrieve user's self identity
func (c *Connector) retrieveSelfIdentity() (response identity, err error) {

	var respIndentities = &identitiesResponse{}

	statusCode, statusText, body, err := c.request("GET", urlRetrieveSelfIdentity, nil)
	if err != nil {
		log.Printf("Failed to get the used user. Error: %v", err)
		return identity{}, err
	}

	switch statusCode {
	case http.StatusOK:
		err = json.Unmarshal(body, respIndentities)
		if err != nil {
			return identity{}, fmt.Errorf("failed to parse identity response: %s, body: %s", err, body)
		}

		if (respIndentities != nil) && (len(respIndentities.Identities) > 0) {
			return respIndentities.Identities[0], nil
		}
	case http.StatusUnauthorized:
		return identity{}, verror.AuthError
	}
	return identity{}, fmt.Errorf("failed to get Self. Status code: %d, Status text: %s", statusCode, statusText)
}

// requestSystemVersion returns the TPP system version of the connector context
func (c *Connector) RetrieveSystemVersion() (string, error) {
	statusCode, status, body, err := c.request("GET", urlResourceSystemStatusVersion, "")
	if err != nil {
		return "", err
	}
	//Put in hint for authentication scope 'configuration'
	switch statusCode {
	case 200:
	case 401:
		return "", fmt.Errorf("http status code '%s' was returned by the server. Hint: OAuth scope 'configuration' is required when using custom fields", status)
	default:
		return "", fmt.Errorf("Unexpected http status code while fetching TPP version. %s", status)
	}

	var response struct{ Version string }
	err = json.Unmarshal(body, &response)
	return response.Version, err
}

func prepareRequest(req *certificate.Request, zone string) (tppReq certificateRequest, err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR, certificate.UserProvidedCSR:
		tppReq.PKCS10 = string(req.GetCSR())
	case certificate.ServiceGeneratedCSR:
		tppReq.Subject = req.Subject.CommonName // TODO: there is some problem because Subject is not only CN
		if !req.OmitSANs {
			tppReq.SubjectAltNames = wrapAltNames(req)
		}
	default:
		return tppReq, fmt.Errorf("Unexpected option in PrivateKeyOrigin")
	}

	tppReq.CertificateType = "AUTO"
	tppReq.PolicyDN = getPolicyDN(zone)
	tppReq.CADN = req.CADN
	tppReq.ObjectName = req.FriendlyName
	tppReq.DisableAutomaticRenewal = true
	customFieldsMap := make(map[string][]string)
	origin := endpoint.SDKName
	for _, f := range req.CustomFields {
		switch f.Type {
		case certificate.CustomFieldPlain:
			customFieldsMap[f.Name] = append(customFieldsMap[f.Name], f.Value)
		case certificate.CustomFieldOrigin:
			origin = f.Value
		}
	}
	tppReq.CASpecificAttributes = append(tppReq.CASpecificAttributes, nameValuePair{Name: "Origin", Value: origin})
	tppReq.Origin = origin

	validityDuration := req.ValidityDuration

	// DEPRECATED: ValidityHours is deprecated in favor of ValidityDuration, but we
	// still support it for backwards compatibility.
	if validityDuration == nil && req.ValidityHours > 0 {
		duration := time.Duration(req.ValidityHours) * time.Hour
		validityDuration = &duration
	}

	if validityDuration != nil {
		formattedExpirationDate := time.Now().Add(*validityDuration).Format(time.RFC3339)

		var attributeNames []string

		switch req.IssuerHint {
		case util.IssuerHintDigicert:
			attributeNames = []string{"DigiCert CA:Specific End Date"}
		case util.IssuerHintMicrosoft:
			attributeNames = []string{"Microsoft CA:Specific End Date"}
		case util.IssuerHintEntrust:
			attributeNames = []string{"EntrustNET CA:Specific End Date"}
		case util.IssuerHintAllIssuers:
			attributeNames = []string{
				"Microsoft CA:Specific End Date",
				"DigiCert CA:Specific End Date",
				"EntrustNET CA:Specific End Date",
				"Specific End Date",
			}
		case util.IssuerHintGeneric:
			attributeNames = []string{"Specific End Date"}
		default:
			return tppReq, fmt.Errorf("invalid issuer hint: %s", req.IssuerHint)
		}

		for _, attributeName := range attributeNames {
			tppReq.CASpecificAttributes = append(tppReq.CASpecificAttributes, nameValuePair{
				Name:  attributeName,
				Value: formattedExpirationDate,
			})
		}
	}

	for name, value := range customFieldsMap {
		tppReq.CustomFields = append(tppReq.CustomFields, customField{name, value})
	}
	if req.Location != nil {
		if req.Location.Instance == "" {
			return tppReq, fmt.Errorf("%w: instance value for Location should not be empty", verror.UserDataError)
		}
		workload := req.Location.Workload
		if workload == "" {
			workload = defaultWorkloadName
		}
		dev := device{
			PolicyDN:   getPolicyDN(zone),
			ObjectName: req.Location.Instance,
			Host:       req.Location.Instance,
			Applications: []application{
				{
					ObjectName: workload,
					Class:      "Basic",
					DriverName: "appbasic",
				},
			},
		}
		if req.Location.TLSAddress != "" {
			host, port, err := parseHostPort(req.Location.TLSAddress)
			if err != nil {
				return tppReq, err
			}
			dev.Applications[0].ValidationHost = host
			dev.Applications[0].ValidationPort = port
		}
		tppReq.Devices = append(tppReq.Devices, dev)
	}
	switch req.KeyType {
	case certificate.KeyTypeRSA:
		tppReq.KeyAlgorithm = "RSA"
		tppReq.KeyBitSize = req.KeyLength
	case certificate.KeyTypeECDSA:
		tppReq.KeyAlgorithm = "ECC"
		tppReq.EllipticCurve = req.KeyCurve.String()
	}

	//Setting the certificate will be re-enabled.
	//From https://docs.venafi.com/Docs/currentSDK/TopNav/Content/SDK/WebSDK/r-SDK-POST-Certificates-request.php
	//Reenable (Optional) The action to control a previously disabled certificate:
	//
	//    - false: Default. Do not renew a previously disabled certificate.
	//    - true: Clear the Disabled attribute, reenable, and then renew the certificate (in this request). Reuse the same CertificateDN, that is also known as a Certificate object.
	tppReq.Reenable = true

	return tppReq, err
}

// RequestCertificate submits the CSR to TPP returning the DN of the requested Certificate
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

// ResetCertificate is an idempotent function, i.e., it won't fail if there is nothing to be
// reset. It returns an error of type *errCertNotFound if the certificate is not
// found.
func (c *Connector) ResetCertificate(req *certificate.Request, restart bool) (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {
	panic("operation is not supported yet")
}

// RetrieveCertificate attempts to retrieve the requested certificate
func (c *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {
	panic("operation is not supported yet")
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {
	panic("operation is not supported yet")
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	panic("operation is not supported yet")
}

func (c *Connector) ReadPolicyConfiguration() (policy *endpoint.Policy, err error) {
	panic("operation is not supported yet")
}

// ReadZoneConfiguration reads the policy data from TPP to get locked and pre-configured values for certificate requests
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
	statusCode, httpStatus, body, err := c.request("POST", urlResourceLog, logReq)
	if err != nil {
		return err
	}

	err = checkLogResponse(statusCode, httpStatus, body)
	if err != nil {
		return err
	}
	return nil
}

func (c *Connector) ListCertificates(filter endpoint.Filter) ([]certificate.CertificateInfo, error) {
	panic("operation is not supported yet")
}

func parseHostPort(s string) (host string, port string, err error) {
	slice := strings.Split(s, ":")
	if len(slice) != 2 {
		err = fmt.Errorf("%w: bad address %s.  should be host:port.", verror.UserDataError, s)
		return
	}
	host = slice[0]
	port = slice[1]
	return
}

func (c *Connector) configDNToGuid(objectDN string) (guid string, err error) {

	req := struct {
		ObjectDN string
	}{
		objectDN,
	}

	var resp struct {
		ClassName        string `json:",omitempty"`
		GUID             string `json:",omitempty"`
		HierarchicalGUID string `json:",omitempty"`
		Revision         int    `json:",omitempty"`
		Result           int    `json:",omitempty"`
	}

	log.Println("Getting guid for object DN", objectDN)
	statusCode, status, body, err := c.request("POST", urlResourceConfigDnToGuid, req)

	if err != nil {
		return guid, err
	}

	if statusCode == http.StatusOK {
		err = json.Unmarshal(body, &resp)
		if err != nil {
			return guid, fmt.Errorf("failed to parse DNtoGuid results: %s, body: %s", err, body)
		}
	} else {
		return guid, fmt.Errorf("request to %s failed: %s\n%s", urlResourceConfigDnToGuid, status, body)
	}

	if statusCode != 200 {
		return "", verror.ServerBadDataResponce
	}

	if resp.Result == 400 {
		log.Printf("object with DN %s doesn't exist", objectDN)
		return "", nil
	}

	if resp.Result != 1 {
		return "", fmt.Errorf("result code %d is not success.", resp.Result)
	}
	return resp.GUID, nil

}

func (c *Connector) findObjectsOfClass(req *findObjectsOfClassRequest) (*findObjectsOfClassResponse, error) {
	statusCode, statusString, body, err := c.request("POST", urlResourceFindObjectsOfClass, req)
	if err != nil {
		return nil, err
	}
	response, err := parseFindObjectsOfClassResponse(statusCode, statusString, body)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// GetZonesByParent returns a list of valid zones for a TPP parent folder specified by parent
func (c *Connector) GetZonesByParent(parent string) ([]string, error) {
	var zones []string

	parentFolderDn := parent
	if !strings.HasPrefix(parentFolderDn, "\\VED\\Policy") {
		parentFolderDn = fmt.Sprintf("\\VED\\Policy\\%s", parentFolderDn)
	}

	request := findObjectsOfClassRequest{
		Class:    "Policy",
		ObjectDN: parentFolderDn,
	}
	response, err := c.findObjectsOfClass(&request)
	if err != nil {
		return nil, err
	}

	for _, folder := range response.PolicyObjects {
		// folder.DN will always start with \VED\Policy but short form is preferrable since both are supported
		zones = append(zones, strings.Replace(folder.DN, "\\VED\\Policy\\", "", 1))
	}
	return zones, nil
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

func checkLogResponse(httpStatusCode int, httpStatus string, body []byte) error {
	switch httpStatusCode {
	case http.StatusOK:
		logData, err := parseLogResponse(body)
		if err != nil {
			return err
		} else if logData.LogResult == 1 {
			return fmt.Errorf("The Log Server failed to store the event in the event log")
		} else {
			return nil
		}
	default:
		return fmt.Errorf("Unexpected status code on TPP Post Log request.\n Status:\n %s. \n Body:\n %s\n", httpStatus, body)
	}
}
