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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/pkg/verror"
	"log"
	"net/http"
	neturl "net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
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

// NewConnector creates a new TPP Connector object used to communicate with TPP
func NewConnector(url string, zone string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	c := Connector{verbose: verbose, trust: trust, zone: zone}
	var err error
	c.baseURL, err = normalizeURL(url)
	if err != nil {
		return nil, err
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

	if strings.HasSuffix(modified, "vedsdk/") {
		modified = modified[:len(modified)-7]
	}
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

//Ping attempts to connect to the TPP Server WebSDK API and returns an errror if it cannot
func (c *Connector) Ping() (err error) {
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
	return fmt.Errorf("failed to authenticate: can't determin valid credentials set")
}

// Get OAuth refresh and access token
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

// Refresh OAuth access token
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

func processAuthData(c *Connector, url urlResource, data interface{}) (resp interface{}, err error) {

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
	return items
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
		return "", fmt.Errorf("%s", err)
	}

	req.PickupID = requestID
	return requestID, nil
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
		type field struct {
			Name  string
			Value *string
		}
		r := struct {
			AttributeData []field
		}{[]field{
			{"X509 SubjectAltName DNS", nil},
			{"X509 SubjectAltName IPAddress", nil},
			{"X509 SubjectAltName RFC822", nil},
			{"X509 SubjectAltName URI", nil},
			{"X509 SubjectAltName OtherName UPN", nil},
		}}
		guid, err := c.configDNToGuid(renewReq.CertificateDN)
		if err != nil {
			return "", err
		}
		statusCode, _, _, err := c.request("PUT", urlResourceCertificate+urlResource(guid), r)
		if err != nil {
			return "", err
		}
		if statusCode != http.StatusOK {
			return "", fmt.Errorf("can't clean SANs values for certificate on server side")
		}
	}
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

func (c *Connector) ImportCertificate(r *certificate.ImportRequest) (*certificate.ImportResponse, error) {

	if r.PolicyDN == "" {
		r.PolicyDN = getPolicyDN(c.zone)
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
