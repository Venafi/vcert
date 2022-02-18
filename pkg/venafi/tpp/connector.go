/*
 * Copyright 2018-2021 Venafi, Inc.
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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/policy"

	"github.com/Venafi/vcert/v4/pkg/util"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/verror"
)

// Connector contains the base data needed to communicate with a TPP Server
type Connector struct {
	baseURL     string
	apiKey      string
	accessToken string
	verbose     bool
	trust       *x509.CertPool
	zone        string
	client      *http.Client
}

func (c *Connector) IsCSRServiceGenerated(req *certificate.Request) (bool, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSshConfig(ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {
	return RetrieveSshConfig(c, ca)
}

func (c *Connector) RetrieveAvailableSSHTemplates() (response []certificate.SshAvaliableTemplate, err error) {
	return GetAvailableSshTemplates(c)
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

//Ping attempts to connect to the TPP Server WebSDK API and returns an error if it cannot
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
		return nil

	} else if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken
		return nil
	}
	return fmt.Errorf("failed to authenticate: can't determine valid credentials set")
}

// GetRefreshToken Get OAuth refresh and access token
func (c *Connector) GetRefreshToken(auth *endpoint.Authentication) (resp OauthGetRefreshTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.Scope == "" {
		auth.Scope = defaultScope
	}
	if auth.ClientId == "" {
		auth.ClientId = defaultClientID
	}

	if auth.User != "" && auth.Password != "" {
		data := oauthGetRefreshTokenRequest{Username: auth.User, Password: auth.Password, Scope: auth.Scope, Client_id: auth.ClientId}
		result, err := processAuthData(c, urlResourceAuthorizeOAuth, data)
		if err != nil {
			return resp, err
		}
		resp = result.(OauthGetRefreshTokenResponse)
		return resp, nil

	} else if auth.ClientPKCS12 {
		data := oauthCertificateTokenRequest{Client_id: auth.ClientId, Scope: auth.Scope}
		result, err := processAuthData(c, urlResourceAuthorizeCertificate, data)
		if err != nil {
			return resp, err
		}

		resp = result.(OauthGetRefreshTokenResponse)
		return resp, nil
	}

	return resp, fmt.Errorf("failed to authenticate: missing credentials")
}

// RefreshAccessToken Refresh OAuth access token
func (c *Connector) RefreshAccessToken(auth *endpoint.Authentication) (resp OauthRefreshAccessTokenResponse, err error) {

	if auth == nil {
		return resp, fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.ClientId == "" {
		auth.ClientId = defaultClientID
	}

	if auth.RefreshToken != "" {
		data := oauthRefreshAccessTokenRequest{Client_id: auth.ClientId, Refresh_token: auth.RefreshToken}
		result, err := processAuthData(c, urlResourceRefreshAccessToken, data)
		if err != nil {
			return resp, err
		}
		resp = result.(OauthRefreshAccessTokenResponse)
		return resp, nil
	} else {
		return resp, fmt.Errorf("failed to authenticate: missing refresh token")
	}
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

	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.AccessToken != "" {
		c.accessToken = auth.AccessToken
		statusCode, statusText, _, err := c.request("GET", urlResource(urlResourceRevokeAccessToken), nil)
		if err != nil {
			return err
		}

		if statusCode == http.StatusOK {
			return nil
		}
		return fmt.Errorf("failed to revoke token. Message: %s", statusText)
	}

	return fmt.Errorf("failed to authenticate: missing access token")
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

	var getRefresh OauthGetRefreshTokenResponse
	var refreshAccess OauthRefreshAccessTokenResponse
	var authorize authorizeResponse

	if statusCode == http.StatusOK {
		switch data.(type) {
		case oauthGetRefreshTokenRequest:
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

func (c *Connector) isAuthServerReachable() (bool, error) {
	url := urlResource(urlResourceAuthorizeIsAuthServer)

	// Extended timeout to allow the server to wake up
	c.getHTTPClient().Timeout = time.Second * 90
	statusCode, statusText, _, err := c.request("GET", url, nil)
	if err != nil {
		return false, fmt.Errorf("error while cheking the authentication server. URL: %s; Error: %v", url, err)
	}

	if statusCode == http.StatusAccepted && strings.Contains(statusText, "Venafi Authentication Server") {
		return true, nil
	}
	return false, fmt.Errorf("invalid authentication server. URL: %s; Status Code: %d; Status Text: %s", url, statusCode, statusText)
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

// requestSystemVersion returns the TPP system version of the connector context
func (c *Connector) requestSystemVersion() (string, error) {
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

// setCertificateMetadata submits the metadata to TPP for storage returning the lock status of the metadata stored
func (c *Connector) setCertificateMetadata(metadataRequest metadataSetRequest) (bool, error) {
	if metadataRequest.DN == "" {
		return false, fmt.Errorf("DN must be provided to setCertificateMetaData")
	}
	if len(metadataRequest.GuidData) == 0 && metadataRequest.KeepExisting {
		return false, nil
	} //Not an error, but there is nothing to do

	statusCode, status, body, err := c.request("POST", urlResourceMetadataSet, metadataRequest)
	if err != nil {
		return false, err
	}
	if statusCode != http.StatusOK {
		return false, fmt.Errorf("Unexpected http status code while setting metadata items. %d-%s", statusCode, status)
	}

	var result = metadataSetResponse{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return false, err
	}

	switch result.Result {
	case 0:
		break
	case 17:
		return false, fmt.Errorf("custom field value not a valid list item. Server returned error %v", result.Result)
	default:
		return false, fmt.Errorf("return code %v was returned while adding metadata to %v. Please refer to the Metadata Result Codes in the TPP WebSDK API documentation to determine if further action is needed", result.Result, metadataRequest.DN)
	}
	return result.Locked, nil
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

	if req.ValidityHours > 0 {

		expirationDateAttribute := ""

		switch req.IssuerHint {
		case util.IssuerHintMicrosoft:
			expirationDateAttribute = "Microsoft CA:Specific End Date"
		case util.IssuerHintDigicert:
			expirationDateAttribute = "DigiCert CA:Specific End Date"
		case util.IssuerHintEntrust:
			expirationDateAttribute = "EntrustNET CA:Specific End Date"
		default:
			expirationDateAttribute = "Specific End Date"
		}

		loc, _ := time.LoadLocation("UTC")
		utcNow := time.Now().In(loc)

		//if the days have decimal parts then round it to next day.
		validityDays := req.ValidityHours / 24

		if req.ValidityHours%24 > 0 {

			validityDays = validityDays + 1

		}

		expirationDate := utcNow.AddDate(0, 0, validityDays)

		formattedExpirationDate := fmt.Sprintf("%d-%02d-%02d %02d:%02d:%02d",
			expirationDate.Year(), expirationDate.Month(), expirationDate.Day(), expirationDate.Hour(), expirationDate.Minute(), expirationDate.Second())

		tppReq.CASpecificAttributes = append(tppReq.CASpecificAttributes, nameValuePair{Name: expirationDateAttribute, Value: formattedExpirationDate})

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

	return tppReq, err
}

func (c *Connector) proccessLocation(req *certificate.Request) error {
	certDN := getCertificateDN(c.zone, req.Subject.CommonName)
	guid, err := c.configDNToGuid(certDN)
	if err != nil {
		return fmt.Errorf("unable to retrieve certificate guid: %s", err)
	}
	if guid == "" {
		if c.verbose {
			log.Printf("certificate with DN %s doesn't exists so no need to check if it is associated with any instances", certDN)
		}
		return nil
	}
	details, err := c.searchCertificateDetails(guid)
	if err != nil {
		return err
	}
	if len(details.Consumers) == 0 {
		log.Printf("There were no instances associated with certificate %s", certDN)
		return nil
	}
	if c.verbose {
		log.Printf("checking associated instances from:\n %s", details.Consumers)
	}
	var device string
	requestedDevice := getDeviceDN(stripBackSlashes(c.zone), *req.Location)

	for _, device = range details.Consumers {
		if c.verbose {
			log.Printf("comparing requested instance %s to %s", requestedDevice, device)
		}
		if device == requestedDevice {
			if req.Location.Replace {
				err = c.dissociate(certDN, device)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("%w: instance %s already exists, change the value or use --replace-instance", verror.UserDataError, device)
			}
		}
	}
	return nil
}

// RequestCertificate submits the CSR to TPP returning the DN of the requested Certificate
func (c *Connector) RequestCertificate(req *certificate.Request) (requestID string, err error) {
	if req.Location != nil {
		err = c.proccessLocation(req)
		if err != nil {
			return
		}
	}
	tppCertificateRequest, err := prepareRequest(req, c.zone)
	if err != nil {
		return "", err
	}
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRequest, tppCertificateRequest)
	if err != nil {
		return "", err
	}
	requestID, err = parseRequestResult(statusCode, status, body)
	if err != nil {
		return "", err
	}
	req.PickupID = requestID

	if len(req.CustomFields) == 0 {
		return
	}

	// Handle legacy TPP custom field API
	//Get the saved metadata for the current certificate, deep compare the
	//saved metadata to the requested metadata. If all items match then no further
	//changes need to be made. If they do not match, they try to update them using
	//the 19.2 WebSDK calls
	metadataItems, err := c.requestMetadataItems(requestID)
	if err != nil {
		log.Println(err)
		return
	}
	//prepare struct for search
	metadata := make(map[string]map[string]struct{})
	for _, item := range metadataItems {
		metadata[item.Key.Label] = make(map[string]struct{})
		for _, v := range item.Value {
			metadata[item.Key.Label][v] = struct{}{} //empty struct has zero size
		}
	}
	//Deep compare the request metadata to the fetched metadata
	var allItemsFound = true
	for _, cf := range tppCertificateRequest.CustomFields {
		values, prs := metadata[cf.Name]
		if !prs {
			allItemsFound = false
			break
		}
		for _, value := range cf.Values {
			_, prs := values[value]
			if !prs {
				//Found the field by name, but couldn't find one of the values
				allItemsFound = false
			}
		}
	}

	if allItemsFound {
		return
	}
	log.Println("Saving metadata custom field using 19.2 method")
	//Create a metadata/set command with the metadata from tppCertificateRequest
	guidItems, err := prepareLegacyMetadata(c, tppCertificateRequest.CustomFields, requestID)
	if err != nil {
		log.Println(err)
		return
	}
	requestData := metadataSetRequest{requestID, guidItems, true}
	//c.request with the metadata request
	_, err = c.setCertificateMetadata(requestData)
	if err != nil {
		log.Println(err)
	}
	return
}

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {
	var ps *policy.PolicySpecification
	var tp policy.TppPolicy

	log.Println("Collecting policy attributes")

	if !strings.HasPrefix(name, util.PathSeparator) {
		name = util.PathSeparator + name
	}

	if !strings.HasPrefix(name, policy.RootPath) {
		name = policy.RootPath + name

	}

	tp.Name = &name

	var checkPolicyResponse policy.CheckPolicyResponse

	req := policy.CheckPolicyRequest{
		PolicyDN: name,
	}
	_, _, body, err := c.request("POST", urlResourceReadPolicy, req)

	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(body, &checkPolicyResponse)
	if err != nil {
		return nil, err
	}

	if checkPolicyResponse.Error != "" {
		return nil, fmt.Errorf(checkPolicyResponse.Error)
	}

	log.Println("Building policy")
	ps, err = policy.BuildPolicySpecificationForTPP(checkPolicyResponse)
	if err != nil {
		return nil, err
	}

	return ps, nil
}

func PolicyExist(policyName string, c *Connector) (bool, error) {

	req := policy.PolicyExistPayloadRequest{
		ObjectDN: policyName,
	}
	_, _, body, err := c.request("POST", urlResourceIsValidPolicy, req)

	if err != nil {
		return false, err
	}
	var response policy.PolicyIsValidResponse
	err = json.Unmarshal(body, &response)

	if err != nil {
		return false, err
	}

	//if error is not null then the policy doesn't exists
	if response.Result == 1 && response.PolicyObject.DN != "" {
		return true, nil
	} else if (response.Error != "") && (response.Result == 400) {
		return false, nil
	} else {
		return false, fmt.Errorf(response.Error)
	}

}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {

	//validate policy specification and policy
	err := policy.ValidateTppPolicySpecification(ps)

	if err != nil {
		return "", err
	}

	log.Printf("policy specification is valid")
	var status = ""
	tppPolicy := policy.BuildTppPolicy(ps)
	if !strings.HasPrefix(name, util.PathSeparator) {
		name = util.PathSeparator + name
	}

	if !strings.HasPrefix(name, policy.RootPath) {
		name = policy.RootPath + name

	}

	tppPolicy.Name = &name

	var policyExists = false

	//validate if the policy exists
	policyExist, err := PolicyExist(name, c)
	if err != nil {
		return "", err
	}

	if policyExist {
		policyExists = true
		log.Printf("found existing policy folder: %s", name)
	} else {

		//validate if the parent exist
		parent := policy.GetParent(name)

		parentExist, err := PolicyExist(parent, c)
		if err != nil {
			return "", err
		}

		if parent != policy.RootPath && !parentExist {

			return "", fmt.Errorf("the policy's parent doesn't exists")

		}
	}

	//step 1 create root policy folder.
	if !policyExists {

		log.Printf("creating policy folder: %s", name)

		req := policy.PolicyPayloadRequest{
			Class:    policy.PolicyClass,
			ObjectDN: *(tppPolicy.Name),
		}

		_, status, _, err = c.request("POST", urlResourceCreatePolicy, req)

		if err != nil {
			return "", err
		}
	}
	//step 2 create policy's attributes.

	log.Printf("updating certificate policy attributes")

	//create Contact
	if tppPolicy.Contact != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppContact, tppPolicy.Contact, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}

	//create Approver
	if tppPolicy.Approver != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppApprover, tppPolicy.Approver, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}
	if policyExists {
		err = resetTPPAttributes(*(tppPolicy.Name), c)
		if err != nil {
			return "", err
		}
	}

	//create Domain Suffix Whitelist
	if tppPolicy.ManagementType != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppManagementType, []string{tppPolicy.ManagementType.Value}, *(tppPolicy.Name), tppPolicy.ManagementType.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Domain Suffix Whitelist
	if tppPolicy.DomainSuffixWhitelist != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppDomainSuffixWhitelist, tppPolicy.DomainSuffixWhitelist, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}

	//create Prohibit Wildcard
	if tppPolicy.ProhibitWildcard != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppProhibitWildcard, []string{strconv.Itoa(*(tppPolicy.ProhibitWildcard))}, *(tppPolicy.Name), false)
		if err != nil {
			return "", err
		}
	}

	//create Certificate Authority
	if tppPolicy.CertificateAuthority != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppCertificateAuthority, []string{*(tppPolicy.CertificateAuthority)}, *(tppPolicy.Name), false)
		if err != nil {
			return "", err
		}
	}

	//create Organization attribute
	if tppPolicy.Organization != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppOrganization, []string{tppPolicy.Organization.Value}, *(tppPolicy.Name), tppPolicy.Organization.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Organizational Unit attribute
	if tppPolicy.OrganizationalUnit != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppOrganizationalUnit, tppPolicy.OrganizationalUnit.Value, *(tppPolicy.Name), tppPolicy.OrganizationalUnit.Locked)
		if err != nil {
			return "", err
		}
	}
	//create City attribute
	if tppPolicy.City != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppCity, []string{tppPolicy.City.Value}, *(tppPolicy.Name), tppPolicy.City.Locked)
		if err != nil {
			return "", err
		}
	}

	//create State attribute
	if tppPolicy.State != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppState, []string{tppPolicy.State.Value}, *(tppPolicy.Name), tppPolicy.State.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Country attribute
	if tppPolicy.Country != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppCountry, []string{tppPolicy.Country.Value}, *(tppPolicy.Name), tppPolicy.Country.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Key Algorithm attribute
	if tppPolicy.KeyAlgorithm != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppKeyAlgorithm, []string{tppPolicy.KeyAlgorithm.Value}, *(tppPolicy.Name), tppPolicy.KeyAlgorithm.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Key Bit Strength
	if tppPolicy.KeyBitStrength != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppKeyBitStrength, []string{tppPolicy.KeyBitStrength.Value}, *(tppPolicy.Name), tppPolicy.KeyBitStrength.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Elliptic Curve attribute
	if tppPolicy.EllipticCurve != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppEllipticCurve, []string{tppPolicy.EllipticCurve.Value}, *(tppPolicy.Name), tppPolicy.EllipticCurve.Locked)
		if err != nil {
			return "", err
		}
	}

	//create Manual Csr attribute
	if tppPolicy.ManualCsr != nil {
		_, status, _, err = createPolicyAttribute(c, policy.ServiceGenerated, []string{tppPolicy.ManualCsr.Value}, *(tppPolicy.Name), tppPolicy.ManualCsr.Locked)
		if err != nil {
			return "", err
		}
	}

	if tppPolicy.ProhibitedSANType != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppProhibitedSANTypes, tppPolicy.ProhibitedSANType, *(tppPolicy.Name), false)
		if err != nil {
			return "", err
		}
	}

	//Allow Private Key Reuse" & "Want Renewal
	if tppPolicy.AllowPrivateKeyReuse != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppAllowPrivateKeyReuse, []string{strconv.Itoa(*(tppPolicy.AllowPrivateKeyReuse))}, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}

	if tppPolicy.WantRenewal != nil {
		_, status, _, err = createPolicyAttribute(c, policy.TppWantRenewal, []string{strconv.Itoa(*(tppPolicy.WantRenewal))}, *(tppPolicy.Name), true)
		if err != nil {
			return "", err
		}
	}

	log.Printf("policy successfully applied to %s", name)

	return status, nil
}

// RetrieveCertificate attempts to retrieve the requested certificate
func (c *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {

	includeChain := req.ChainOption != certificate.ChainOptionIgnore
	rootFirstOrder := includeChain && req.ChainOption == certificate.ChainOptionRootFirst

	if req.PickupID == "" && req.Thumbprint != "" {
		// search cert by Thumbprint and fill pickupID
		searchResult, err := c.searchCertificatesByFingerprint(req.Thumbprint)
		if err != nil {
			return nil, fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return nil, fmt.Errorf("No certifiate found using fingerprint %s", req.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return nil, fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}
		req.PickupID = searchResult.Certificates[0].CertificateRequestId
	}

	certReq := certificateRetrieveRequest{
		CertificateDN:  req.PickupID,
		Format:         "base64",
		RootFirstOrder: rootFirstOrder,
		IncludeChain:   includeChain,
	}
	if req.CsrOrigin == certificate.ServiceGeneratedCSR || req.FetchPrivateKey {
		certReq.IncludePrivateKey = true
		if req.KeyType == certificate.KeyTypeRSA {
			certReq.Format = "Base64 (PKCS #8)"
		}
		certReq.Password = req.KeyPassword
	}

	startTime := time.Now()
	for {
		var retrieveResponse *certificateRetrieveResponse
		retrieveResponse, err = c.retrieveCertificateOnce(certReq)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve: %s", err)
		}
		if retrieveResponse.CertificateData != "" {
			certificates, err = newPEMCollectionFromResponse(retrieveResponse.CertificateData, req.ChainOption)
			if err != nil {
				return
			}
			err = req.CheckCertificate(certificates.Certificate)
			return
		}
		if req.Timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: retrieveResponse.Status}
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}
}

func (c *Connector) retrieveCertificateOnce(certReq certificateRetrieveRequest) (*certificateRetrieveResponse, error) {
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRetrieve, certReq)
	if err != nil {
		return nil, err
	}
	retrieveResponse, err := parseRetrieveResult(statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return &retrieveResponse, nil
}

func (c *Connector) putCertificateInfo(dn string, attributes []nameSliceValuePair) error {
	guid, err := c.configDNToGuid(dn)
	if err != nil {
		return err
	}
	statusCode, _, _, err := c.request("PUT", urlResourceCertificate+urlResource(guid), struct{ AttributeData []nameSliceValuePair }{attributes})
	if err != nil {
		return err
	}
	if statusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %v", statusCode)
	}
	return nil
}

func (c *Connector) prepareRenewalRequest(renewReq *certificate.RenewalRequest) error {
	if renewReq.CertificateRequest != nil && len(renewReq.CertificateRequest.GetCSR()) != 0 {
		return nil
	}

	searchReq := &certificate.Request{
		PickupID: renewReq.CertificateDN,
	}

	// here we fetch old cert anyway
	oldPcc, err := c.RetrieveCertificate(searchReq)
	if err != nil {
		return fmt.Errorf("Failed to fetch old certificate by id %s: %s", renewReq.CertificateDN, err)
	}
	oldCertBlock, _ := pem.Decode([]byte(oldPcc.Certificate))
	if oldCertBlock == nil || oldCertBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("Failed to fetch old certificate by id %s: PEM parse error", renewReq.CertificateDN)
	}
	oldCert, err := x509.ParseCertificate([]byte(oldCertBlock.Bytes))
	if err != nil {
		return fmt.Errorf("Failed to fetch old certificate by id %s: %s", renewReq.CertificateDN, err)
	}
	if renewReq.CertificateRequest == nil {
		renewReq.CertificateRequest = certificate.NewRequest(oldCert)
	}
	err = c.GenerateRequest(&endpoint.ZoneConfiguration{}, renewReq.CertificateRequest)
	return err
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {
	if renewReq.Thumbprint != "" && renewReq.CertificateDN == "" {
		// search by Thumbprint and fill *renewReq.CertificateDN
		searchResult, err := c.searchCertificatesByFingerprint(renewReq.Thumbprint)
		if err != nil {
			return "", fmt.Errorf("Failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return "", fmt.Errorf("No certifiate found using fingerprint %s", renewReq.Thumbprint)
		}
		if len(searchResult.Certificates) > 1 {
			return "", fmt.Errorf("Error: more than one CertificateRequestId was found with the same thumbprint")
		}

		renewReq.CertificateDN = searchResult.Certificates[0].CertificateRequestId
	}
	if renewReq.CertificateDN == "" {
		return "", fmt.Errorf("failed to create renewal request: CertificateDN or Thumbprint required")
	}
	if renewReq.CertificateRequest != nil && renewReq.CertificateRequest.OmitSANs {
		// if OmitSANSs flag is presented we need to clean SANs values in TPP
		// for preventing adding them to renew request on TPP side
		err = c.putCertificateInfo(renewReq.CertificateDN, []nameSliceValuePair{
			{"X509 SubjectAltName DNS", nil},
			{"X509 SubjectAltName IPAddress", nil},
			{"X509 SubjectAltName RFC822", nil},
			{"X509 SubjectAltName URI", nil},
			{"X509 SubjectAltName OtherName UPN", nil},
		})
		if err != nil {
			return "", fmt.Errorf("can't clean SANs values for certificate on server side: %v", err)
		}
	}
	//err = c.prepareRenewalRequest(renewReq) todo: uncomment on refactoring
	//if err != nil {
	//	return "", err
	//}
	var r = certificateRenewRequest{}
	r.CertificateDN = renewReq.CertificateDN
	if renewReq.CertificateRequest != nil && len(renewReq.CertificateRequest.GetCSR()) != 0 {
		r.PKCS10 = string(renewReq.CertificateRequest.GetCSR())
	}
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRenew, r)
	if err != nil {
		return "", err
	}

	response, err := parseRenewResult(statusCode, status, body)
	if err != nil {
		return "", err
	}
	if !response.Success {
		return "", fmt.Errorf("Certificate Renewal error: %s", response.Error)
	}
	return renewReq.CertificateDN, nil
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	reason, ok := RevocationReasonsMap[revReq.Reason]
	if !ok {
		return fmt.Errorf("could not parse revocation reason `%s`", revReq.Reason)
	}

	var r = certificateRevokeRequest{
		revReq.CertificateDN,
		revReq.Thumbprint,
		reason,
		revReq.Comments,
		revReq.Disable,
	}
	statusCode, status, body, err := c.request("POST", urlResourceCertificateRevoke, r)
	if err != nil {
		return err
	}
	revokeResponse, err := parseRevokeResult(statusCode, status, body)
	if err != nil {
		return
	}
	if !revokeResponse.Success {
		return fmt.Errorf("Revocation error: %s", revokeResponse.Error)
	}
	return
}

var zoneNonFoundregexp = regexp.MustCompile("PolicyDN: .+ does not exist")

func (c *Connector) ReadPolicyConfiguration() (policy *endpoint.Policy, err error) {
	if c.zone == "" {
		return nil, fmt.Errorf("empty zone")
	}
	rq := struct{ PolicyDN string }{getPolicyDN(c.zone)}
	statusCode, status, body, err := c.request("POST", urlResourceCertificatePolicy, rq)
	if err != nil {
		return
	}
	var r struct {
		Policy serverPolicy
		Error  string
	}
	if statusCode == http.StatusOK {
		err = json.Unmarshal(body, &r)
		if err != nil {
			return nil, err
		}
		p := r.Policy.toPolicy()
		policy = &p
	} else if statusCode == http.StatusBadRequest {
		err = json.Unmarshal(body, &r)
		if err != nil {
			return nil, err
		}
		if zoneNonFoundregexp.Match([]byte(r.Error)) {
			return nil, verror.ZoneNotFoundError
		}
	} else {
		return nil, fmt.Errorf("Invalid status: %s Server data: %s", status, body)
	}
	return
}

//ReadZoneConfiguration reads the policy data from TPP to get locked and pre-configured values for certificate requests
func (c *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	if c.zone == "" {
		return nil, fmt.Errorf("empty zone")
	}
	zoneConfig := endpoint.NewZoneConfiguration()
	zoneConfig.HashAlgorithm = x509.SHA256WithRSA //todo: check this can have problem with ECDSA key
	rq := struct{ PolicyDN string }{getPolicyDN(c.zone)}
	statusCode, status, body, err := c.request("POST", urlResourceCertificatePolicy, rq)
	if err != nil {
		return
	}
	var r struct {
		Policy serverPolicy
		Error  string
	}
	if statusCode == http.StatusOK {
		err = json.Unmarshal(body, &r)
		if err != nil {
			return nil, err
		}
		p := r.Policy.toPolicy()
		r.Policy.toZoneConfig(zoneConfig)
		zoneConfig.Policy = p
		return zoneConfig, nil
	} else if statusCode == http.StatusBadRequest {
		err = json.Unmarshal(body, &r)
		if err != nil {
			return nil, err
		}
		if zoneNonFoundregexp.Match([]byte(r.Error)) {
			return nil, verror.ZoneNotFoundError
		}
	}
	return nil, fmt.Errorf("Invalid status: %s Server response: %s", status, string(body))

}

func (c *Connector) ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	r := importRequest{
		PolicyDN:        req.PolicyDN,
		ObjectName:      req.ObjectName,
		CertificateData: req.CertificateData,
		PrivateKeyData:  req.PrivateKeyData,
		Password:        req.Password,
		Reconcile:       req.Reconcile,
	}

	if r.PolicyDN == "" {
		r.PolicyDN = getPolicyDN(c.zone)
	}

	origin := endpoint.SDKName + " (+)" // standard suffix needed to differentiate certificates imported from enrolled in TPP
	for _, f := range req.CustomFields {
		if f.Type == certificate.CustomFieldOrigin {
			origin = f.Value + " (+)"
		}
	}
	statusCode, _, body, err := c.request("POST", urlResourceCertificateImport, r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerTemporaryUnavailableError, err)
	}
	switch statusCode {
	case http.StatusOK:
		var response = &certificate.ImportResponse{}
		err := json.Unmarshal(body, response)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode import response message: %s", verror.ServerError, err)
		}
		err = c.putCertificateInfo(response.CertificateDN, []nameSliceValuePair{{Name: "Origin", Value: []string{origin}}})
		if err != nil {
			log.Println(err)
		}
		return response, nil
	case http.StatusBadRequest:
		var errorResponse = &struct{ Error string }{}
		err := json.Unmarshal(body, errorResponse)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to decode error message: %s", verror.ServerBadDataResponce, err)
		}
		return nil, fmt.Errorf("%w: can't import certificate %s", verror.ServerBadDataResponce, errorResponse.Error)
	default:
		return nil, fmt.Errorf("%w: unexpected response status %d: %s", verror.ServerTemporaryUnavailableError, statusCode, string(body))
	}
}

func (c *Connector) SearchCertificates(req *certificate.SearchRequest) (*certificate.CertSearchResponse, error) {

	var err error

	url := fmt.Sprintf("%s?%s", urlResourceCertificateSearch, strings.Join(*req, "&"))
	statusCode, _, body, err := c.request("GET", urlResource(url), nil)
	if err != nil {
		return nil, err
	}
	searchResult, err := ParseCertificateSearchResponse(statusCode, body)
	if err != nil {
		return nil, err
	}
	return searchResult, nil
}

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Connector) ListCertificates(filter endpoint.Filter) ([]certificate.CertificateInfo, error) {
	if c.zone == "" {
		return nil, fmt.Errorf("empty zone")
	}
	min := func(i, j int) int {
		if i < j {
			return i
		}
		return j
	}
	const batchSize = 500
	limit := 100000000
	if filter.Limit != nil {
		limit = *filter.Limit
	}
	var buf [][]certificate.CertificateInfo
	for offset := 0; limit > 0; limit, offset = limit-batchSize, offset+batchSize {
		var b []certificate.CertificateInfo
		var err error
		b, err = c.getCertsBatch(offset, min(limit, batchSize), filter.WithExpired)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b)
		if len(b) < min(limit, batchSize) {
			break
		}
	}
	sumLen := 0
	for _, b := range buf {
		sumLen += len(b)
	}
	infos := make([]certificate.CertificateInfo, sumLen)
	offset := 0
	for _, b := range buf {
		copy(infos[offset:], b[:])
		offset += len(b)
	}
	return infos, nil
}

func (c *Connector) getCertsBatch(offset, limit int, withExpired bool) ([]certificate.CertificateInfo, error) {
	url := urlResourceCertificatesList + urlResource(
		"?ParentDNRecursive="+neturl.QueryEscape(getPolicyDN(c.zone))+
			"&limit="+fmt.Sprintf("%d", limit)+
			"&offset="+fmt.Sprintf("%d", offset))
	if !withExpired {
		url += urlResource("&ValidToGreater=" + neturl.QueryEscape(time.Now().Format(time.RFC3339)))
	}
	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if statusCode != 200 {
		return nil, fmt.Errorf("can`t get certificates list: %d %s\n%s", statusCode, status, string(body))
	}
	var r struct {
		Certificates []struct {
			DN   string
			X509 certificate.CertificateInfo
		}
	}
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}
	infos := make([]certificate.CertificateInfo, len(r.Certificates))
	for i, c := range r.Certificates {
		c.X509.ID = c.DN
		infos[i] = c.X509
	}
	return infos, nil
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

func (c *Connector) dissociate(certDN, applicationDN string) error {
	req := struct {
		CertificateDN string
		ApplicationDN []string
		DeleteOrphans bool
	}{
		certDN,
		[]string{applicationDN},
		true,
	}
	log.Println("Dissociating device", applicationDN)
	statusCode, status, body, err := c.request("POST", urlResourceCertificatesDissociate, req)
	if err != nil {
		return err
	}
	if statusCode != 200 {
		return fmt.Errorf("%w: We have problem with server response.\n  status: %s\n  body: %s\n", verror.ServerBadDataResponce, status, body)
	}
	return nil
}

func (c *Connector) associate(certDN, applicationDN string, pushToNew bool) error {
	req := struct {
		CertificateDN string
		ApplicationDN []string
		PushToNew     bool
	}{
		certDN,
		[]string{applicationDN},
		pushToNew,
	}
	log.Println("Associating device", applicationDN)
	statusCode, status, body, err := c.request("POST", urlResourceCertificatesAssociate, req)
	if err != nil {
		return err
	}
	if statusCode != 200 {
		log.Printf("We have problem with server response.\n  status: %s\n  body: %s\n", status, body)
		return verror.ServerBadDataResponce
	}
	return nil
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

func createPolicyAttribute(c *Connector, at string, av []string, n string, l bool) (statusCode int, statusText string, body []byte, err error) {

	request := policy.PolicySetAttributePayloadRequest{
		Locked:        l,
		ObjectDN:      n,
		Class:         policy.PolicyAttributeClass,
		AttributeName: at,
		Values:        av,
	}
	// if is locked is a policy value
	// if is not locked then is a default.

	statusCode, statusText, body, err = c.request("POST", urlResourceWritePolicy, request)
	if err != nil {
		return statusCode, statusText, body, err
	}

	var response policy.PolicySetAttributeResponse

	err = json.Unmarshal(body, &response)
	if err != nil {
		return statusCode, statusText, body, err
	}

	if response.Error != "" {
		err = fmt.Errorf(response.Error)
		return statusCode, statusText, body, err
	}

	return statusCode, statusText, body, err
}

func getPolicyAttribute(c *Connector, at string, n string) (s []string, b *bool, err error) {

	request := policy.PolicyGetAttributePayloadRequest{
		ObjectDN:      n,
		Class:         policy.PolicyAttributeClass,
		AttributeName: at,
		Values:        []string{"1"},
	}
	// if is locked is a policy value
	// if is not locked then is a default.
	_, _, body, err := c.request("POST", urlResourceReadPolicy, request)
	if err != nil {
		return nil, nil, err
	}

	var response policy.PolicyGetAttributeResponse
	err = json.Unmarshal(body, &response)

	if err != nil {
		return nil, nil, err
	}

	if len(response.Values) > 0 {
		return response.Values, &response.Locked, nil
	}
	//no value set and no error.
	return nil, nil, nil
}

func resetTPPAttributes(zone string, c *Connector) error {

	//reset Domain Suffix Whitelist
	err := resetTPPAttribute(c, policy.TppDomainSuffixWhitelist, zone)
	if err != nil {
		return err
	}

	//reset Prohibit Wildcard
	err = resetTPPAttribute(c, policy.TppProhibitWildcard, zone)
	if err != nil {
		return err
	}

	//reset Certificate Authority
	err = resetTPPAttribute(c, policy.TppCertificateAuthority, zone)
	if err != nil {
		return err
	}

	//reset Organization attribute
	err = resetTPPAttribute(c, policy.TppOrganization, zone)
	if err != nil {
		return err
	}

	//reset Organizational Unit attribute
	err = resetTPPAttribute(c, policy.TppOrganizationalUnit, zone)
	if err != nil {
		return err
	}

	//reset City attribute
	err = resetTPPAttribute(c, policy.TppCity, zone)
	if err != nil {
		return err
	}

	//reset State attribute
	err = resetTPPAttribute(c, policy.TppState, zone)
	if err != nil {
		return err
	}

	//reset Country attribute
	err = resetTPPAttribute(c, policy.TppCountry, zone)
	if err != nil {
		return err
	}

	//reset Key Algorithm attribute
	err = resetTPPAttribute(c, policy.TppKeyAlgorithm, zone)
	if err != nil {
		return err
	}

	//reset Key Bit Strength
	err = resetTPPAttribute(c, policy.TppKeyBitStrength, zone)
	if err != nil {
		return err
	}

	//reset Elliptic Curve attribute
	err = resetTPPAttribute(c, policy.TppEllipticCurve, zone)
	if err != nil {
		return err
	}

	//reset Manual Csr attribute
	err = resetTPPAttribute(c, policy.ServiceGenerated, zone)
	if err != nil {
		return err
	}

	//reset Manual Csr attribute
	err = resetTPPAttribute(c, policy.TppProhibitedSANTypes, zone)
	if err != nil {
		return err
	}

	//reset Allow Private Key Reuse" & "Want Renewal
	err = resetTPPAttribute(c, policy.TppAllowPrivateKeyReuse, zone)
	if err != nil {
		return err
	}

	err = resetTPPAttribute(c, policy.TppWantRenewal, zone)
	if err != nil {
		return err
	}

	err = resetTPPAttribute(c, policy.TppManagementType, zone)
	if err != nil {
		return err
	}

	return nil
}

func resetTPPAttribute(c *Connector, at, zone string) error {

	request := policy.ClearTTPAttributesRequest{
		ObjectDN:      zone,
		Class:         policy.PolicyAttributeClass,
		AttributeName: at,
	}
	// if is locked is a policy value
	// if is not locked then is a default.

	_, _, body, err := c.request("POST", urlResourceCleanPolicy, request)
	if err != nil {
		return err
	}

	var response policy.PolicySetAttributeResponse

	err = json.Unmarshal(body, &response)
	if err != nil {
		return err
	}

	if response.Error != "" {
		err = fmt.Errorf(response.Error)
		return err
	}

	return nil
}

func (c *Connector) RequestSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {

	return RequestSshCertificate(c, req)

}

func (c *Connector) RetrieveSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	return RetrieveSshCertificate(c, req)
}

func (c *Connector) RetrieveCertificateMetaData(dn string) (*certificate.CertificateMetaData, error) {

	//first step convert dn to guid
	request := DNToGUIDRequest{ObjectDN: dn}
	statusCode, status, body, err := c.request("POST", urlResourceDNToGUID, request)

	if err != nil {
		return nil, err
	}

	guidInfo, err := parseDNToGUIDRequestResponse(statusCode, status, body)

	if err != nil {
		return nil, err
	}

	//second step get certificate metadata
	url := fmt.Sprintf("%s%s", urlResourceCertificate, guidInfo.GUID)

	statusCode, status, body, err = c.request("GET", urlResource(url), nil)

	if err != nil {
		return nil, err
	}

	data, err := parseCertificateMetaData(statusCode, status, body)
	if err != nil {
		return nil, err
	}

	return data, nil

}

func parseDNToGUIDRequestResponse(httpStatusCode int, httpStatus string, body []byte) (*DNToGUIDResponse, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		reqData, err := parseDNToGUIDResponseData(body)
		if err != nil {
			return nil, err
		}
		return reqData, nil
	default:
		return nil, fmt.Errorf("Unexpected status code on TPP DN to GUID request.\n Status:\n %s. \n Body:\n %s\n", httpStatus, body)
	}
}

func parseDNToGUIDResponseData(b []byte) (data *DNToGUIDResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseCertificateMetaData(httpStatusCode int, httpStatus string, body []byte) (*certificate.CertificateMetaData, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		reqData, err := parseCertificateMetaDataResponse(body)
		if err != nil {
			return nil, err
		}
		return reqData, nil
	default:
		return nil, fmt.Errorf("Unexpected status code on TPP DN to GUID request.\n Status:\n %s. \n Body:\n %s\n", httpStatus, body)
	}
}

func parseCertificateMetaDataResponse(b []byte) (data *certificate.CertificateMetaData, err error) {
	err = json.Unmarshal(b, &data)
	return
}
