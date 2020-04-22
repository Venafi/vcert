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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/Venafi/vcert/pkg/verror"
)

const defaultKeySize = 2048
const defaultSignatureAlgorithm = x509.SHA256WithRSA
const defaultClientID = "vcert-sdk"
const defaultScope = "certificate:manage,revoke"
const defaultWorkloadName = "Default"

type customField struct {
	Name   string
	Values []string
}

type application struct {
	ObjectName     string
	Class          string
	DriverName     string
	ValidationHost string `json:",omitempty"`
	ValidationPort string `json:",omitempty"`
}

type device struct {
	PolicyDN     string
	ObjectName   string
	Host         string
	Applications []application
}

type certificateRequest struct {
	PolicyDN                string          `json:",omitempty"`
	CADN                    string          `json:",omitempty"`
	ObjectName              string          `json:",omitempty"`
	Subject                 string          `json:",omitempty"`
	OrganizationalUnit      string          `json:",omitempty"`
	Organization            string          `json:",omitempty"`
	City                    string          `json:",omitempty"`
	State                   string          `json:",omitempty"`
	Country                 string          `json:",omitempty"`
	SubjectAltNames         []sanItem       `json:",omitempty"`
	Contact                 string          `json:",omitempty"`
	CASpecificAttributes    []nameValuePair `json:",omitempty"`
	Origin                  string          `json:",omitempty"`
	PKCS10                  string          `json:",omitempty"`
	KeyAlgorithm            string          `json:",omitempty"`
	KeyBitSize              int             `json:",omitempty"`
	EllipticCurve           string          `json:",omitempty"`
	DisableAutomaticRenewal bool            `json:",omitempty"`
	CustomFields            []customField   `json:",omitempty"`
	Devices                 []device        `json:",omitempty"`
}

type certificateRetrieveRequest struct {
	CertificateDN     string `json:",omitempty"`
	Format            string `json:",omitempty"`
	Password          string `json:",omitempty"`
	IncludePrivateKey bool   `json:",omitempty"`
	IncludeChain      bool   `json:",omitempty"`
	FriendlyName      string `json:",omitempty"`
	RootFirstOrder    bool   `json:",omitempty"`
}

type certificateRetrieveResponse struct {
	CertificateData string `json:",omitempty"`
	Format          string `json:",omitempty"`
	Filename        string `json:",omitempty"`
	Status          string `json:",omitempty"`
	Stage           int    `json:",omitempty"`
}

type RevocationReason int

// RevocationReasonsMap maps *certificate.RevocationRequest.Reason to TPP-specific webSDK codes
var RevocationReasonsMap = map[string]RevocationReason{
	"":                       0, // NoReason
	"none":                   0, //
	"key-compromise":         1, // UserKeyCompromised
	"ca-compromise":          2, // CAKeyCompromised
	"affiliation-changed":    3, // UserChangedAffiliation
	"superseded":             4, // CertificateSuperseded
	"cessation-of-operation": 5, // OriginalUseNoLongerValid
}

type certificateRevokeRequest struct {
	CertificateDN string           `json:",omitempty"`
	Thumbprint    string           `json:",omitempty"`
	Reason        RevocationReason `json:",omitempty"`
	Comments      string           `json:",omitempty"`
	Disable       bool             `json:",omitempty"`
}

/* {Requested:true  Success:true Error:} -- means requested
   {Requested:false Success:true Error:} -- means already revoked  */
type certificateRevokeResponse struct {
	Requested bool   `json:",omitempty"`
	Success   bool   `json:",omitempty"`
	Error     string `json:",omitempty"`
}

type certificateRenewRequest struct {
	CertificateDN string `json:",omitempty"`
	PKCS10        string `json:",omitempty"`
}

type certificateRenewResponse struct {
	Success bool   `json:",omitempty"`
	Error   string `json:",omitempty"`
}

type sanItem struct {
	Type int    `json:",omitempty"`
	Name string `json:",omitempty"`
}

type nameValuePair struct {
	Name  string `json:",omitempty"`
	Value string `json:",omitempty"`
}

type nameSliceValuePair struct {
	Name  string
	Value []string
}

type certificateRequestResponse struct {
	CertificateDN string `json:",omitempty"`
	Error         string `json:",omitempty"`
}

type importRequest struct {
	PolicyDN        string `json:",omitempty"`
	ObjectName      string `json:",omitempty"`
	CertificateData string `json:",omitempty"`
	PrivateKeyData  string `json:",omitempty"`
	Password        string `json:",omitempty"`
	Reconcile       bool   `json:",omitempty"`
}

type authorizeResponse struct {
	APIKey     string `json:",omitempty"`
	ValidUntil string `json:",omitempty"` //todo: add usage
}

type authorizeResquest struct {
	Username string `json:",omitempty"`
	Password string `json:",omitempty"`
}

type refreshAccessTokenResquest struct {
	Client_id     string `json:"client_id"`
	Refresh_token string `json:"refresh_token"`
}

type oauthGetRefreshTokenRequest struct {
	Client_id string `json:"client_id"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Scope     string `json:"scope"`
}
type OauthGetRefreshTokenResponse struct {
	Access_token  string `json:"access_token,omitempty"`
	Expires       int    `json:"expires,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Refresh_token string `json:"refresh_token,omitempty"`
	Scope         string `json:"scope,omitempty"`
	Token_type    string `json:"token_type,omitempty"`
}

type oauthRefreshAccessTokenRequest struct {
	Refresh_token string `json:"refresh_token,omitempty"`
	Client_id     string `json:"client_id"`
}

type oauthCertificateTokenRequest struct {
	Client_id string `json:"client_id"`
	Scope     string `json:"scope,omitempty"`
}

type OauthRefreshAccessTokenResponse struct {
	Access_token  string `json:"access_token,omitempty"`
	Expires       int    `json:"expires,omitempty"`
	Identity      string `json:"identity,omitempty"`
	Refresh_token string `json:"refresh_token,omitempty"`
	Token_type    string `json:"token_type,omitempty"`
}
type policyRequest struct {
	ObjectDN      string `json:",omitempty"`
	Class         string `json:",omitempty"`
	AttributeName string `json:",omitempty"`
}
type metadataItem struct {
	AllowedValues     []string `json:",omitempty"`
	Classes           []string `json:",omitempty"`
	ConfigAttribute   string   `json:",omitempty"`
	DefaultValues     []string `json:",omitempty"`
	DN                string   `json:",omitempty"`
	ErrorMessage      string   `json:",omitempty"`
	Guid              string   `json:",omitempty"`
	Help              string   `json:",omitempty"`
	Label             string   `json:",omitempty"`
	Name              string   `json:",omitempty"`
	Policyable        bool     `json:",omitempty"`
	RegularExpression string   `json:",omitempty"`
	RenderHidden      bool     `json:",omitempty"`
	RenderReadOnly    bool     `json:",omitempty"`
	Type              int      `json:",omitempty"`
}
type metadataKeyValueSet struct {
	Key   metadataItem `json:",omitempty"`
	Value []string     `json:",omitempty"`
}

type metadataGetItemsRequest struct {
	ObjectDN string `json:"DN"`
}
type metadataGetItemsResponse struct {
	Items  []metadataItem `json:",omitempty"`
	Locked bool           `json:",omitempty"`
}
type metadataGetResponse struct {
	Data   []metadataKeyValueSet
	Locked bool `json:",omitempty"`
}
type guidData struct {
	ItemGuid string   `json:",omitempty"`
	List     []string `json:",omitempty"`
}
type metadataSetRequest struct {
	DN           string     `json:"DN"`
	GuidData     []guidData `json:"GuidData"`
	KeepExisting bool       `json:"KeepExisting"`
}
type metadataSetResponse struct {
	Locked bool `json:",omitempty"`
	Result int  `json:",omitempty"`
}

type ConfigAttribute struct {
	Name  string
	Value []string
}

type ConfigWriteRequest struct {
	ObjectDN      string
	AttributeData []ConfigAttribute
}

type systemStatusVersionResponse string

type urlResource string

const (
	urlResourceAuthorize              urlResource = "vedsdk/authorize/"
	urlResourceAuthorizeCertificate   urlResource = "vedauth/Authorize/Certificate"
	urlResourceAuthorizeOAuth         urlResource = "vedauth/authorize/oauth"
	urlResourceCertificateImport      urlResource = "vedsdk/certificates/import"
	urlResourceCertificatePolicy      urlResource = "vedsdk/certificates/checkpolicy"
	urlResourceCertificateRenew       urlResource = "vedsdk/certificates/renew"
	urlResourceCertificateRequest     urlResource = "vedsdk/certificates/request"
	urlResourceCertificateRetrieve    urlResource = "vedsdk/certificates/retrieve"
	urlResourceCertificateRevoke      urlResource = "vedsdk/certificates/revoke"
	urlResourceCertificatesAssociate  urlResource = "vedsdk/Certificates/Associate"
	urlResourceCertificatesDissociate urlResource = "vedsdk/Certificates/Dissociate"
	urlResourceCertificate            urlResource = "vedsdk/certificates/"
	urlResourceCertificateSearch                  = urlResourceCertificate
	urlResourceCertificatesList                   = urlResourceCertificate
	urlResourceConfigDnToGuid         urlResource = "vedsdk/Config/DnToGuid"
	urlResourceConfigReadDn           urlResource = "vedsdk/Config/ReadDn"
	urlResourceConfigWrite            urlResource = "vedsdk/Config/Write"
	urlResourceFindPolicy             urlResource = "vedsdk/config/findpolicy"
	urlResourceRefreshAccessToken     urlResource = "vedauth/authorize/token" // #nosec
	urlResourceMetadataSet            urlResource = "vedsdk/metadata/set"
	urlResourceAllMetadataGet         urlResource = "vedsdk/metadata/getitems"
	urlResourceMetadataGet            urlResource = "vedsdk/metadata/get"
	urlResourceSystemStatusVersion    urlResource = "vedsdk/SystemStatus/Version"
)

const (
	tppAttributeOrg            = "Organization"
	tppAttributeOrgUnit        = "Organizational Unit"
	tppAttributeCountry        = "Country"
	tppAttributeState          = "State"
	tppAttributeLocality       = "City"
	tppAttributeKeyAlgorithm   = "Key Algorithm"
	tppAttributeKeySize        = "Key Bit Strength"
	tppAttributeEllipticCurve  = "Elliptic Curve"
	tppAttributeRequestHash    = "PKCS10 Hash Algorithm"
	tppAttributeManagementType = "Management Type"
	tppAttributeManualCSR      = "Manual Csr"
)

type tppPolicyData struct {
	Error  string   `json:",omitempty"`
	Result int      `json:",omitempty"`
	Values []string `json:",omitempty"`
	Locked bool     `json:",omitempty"`
}

type retrieveChainOption int

const (
	retrieveChainOptionRootLast retrieveChainOption = iota
	retrieveChainOptionRootFirst
	retrieveChainOptionIgnore
)

const (
	pkcs10HashAlgorithmSha1   = 0
	pkcs10HashAlgorithmSha256 = 1
	pkcs10HashAlgorithmSha384 = 2
	pkcs10HashAlgorithmSha512 = 3
)

func retrieveChainOptionFromString(order string) retrieveChainOption {
	switch strings.ToLower(order) {
	case "root-first":
		return retrieveChainOptionRootFirst
	case "ignore":
		return retrieveChainOptionIgnore
	default:
		return retrieveChainOptionRootLast
	}
}

func (c *Connector) getURL(resource urlResource) (string, error) {
	if c.baseURL == "" {
		return "", fmt.Errorf("The Host URL has not been set")
	}
	return fmt.Sprintf("%s%s", c.baseURL, resource), nil
}

func (c *Connector) request(method string, resource urlResource, data interface{}) (statusCode int, statusText string, body []byte, err error) {
	url, err := c.getURL(resource)
	if err != nil {
		return
	}
	var payload io.Reader
	var b []byte
	if method == "POST" || method == "PUT" {
		b, _ = json.Marshal(data)
		payload = bytes.NewReader(b)
	}

	r, _ := http.NewRequest(method, url, payload)
	r.Close = true
	if c.accessToken != "" {
		r.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	} else if c.apiKey != "" {
		r.Header.Add("x-venafi-api-key", c.apiKey)
	}
	r.Header.Add("content-type", "application/json")
	r.Header.Add("cache-control", "no-cache")

	res, err := c.getHTTPClient().Do(r)
	if res != nil {
		statusCode = res.StatusCode
		statusText = res.Status
	}
	if err != nil {
		return
	}

	defer res.Body.Close()
	body, err = ioutil.ReadAll(res.Body)
	// Do not enable trace in production
	trace := false // IMPORTANT: sensitive information can be diclosured
	// I hope you know what are you doing
	if trace {
		log.Println("#################")
		log.Printf("Headers are:\n%s", r.Header)
		if method == "POST" || method == "PUT" {
			log.Printf("JSON sent for %s\n%s\n", url, string(b))
		} else {
			log.Printf("%s request sent to %s\n", method, url)
		}
		log.Printf("Response:\n%s\n", string(body))
	} else if c.verbose {
		log.Printf("Got %s status for %s %s\n", statusText, method, url)
	}
	return
}

func (c *Connector) getHTTPClient() *http.Client {
	if c.client != nil {
		return c.client
	}
	var netTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	if c.trust != nil {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.RootCAs = c.trust
	}
	netTransport.TLSClientConfig = tlsConfig
	c.client = &http.Client{
		Timeout:   time.Second * 10,
		Transport: netTransport,
	}
	return c.client
}

// GenerateRequest creates a new certificate request, based on the zone/policy configuration and the user data
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	if config == nil {
		config, err = c.ReadZoneConfiguration()
		if err != nil {
			return fmt.Errorf("could not read zone configuration: %s", err)
		}
	}

	tppMgmtType := config.CustomAttributeValues[tppAttributeManagementType]
	if tppMgmtType == "Monitoring" || tppMgmtType == "Unassigned" {
		return fmt.Errorf("Unable to request certificate from TPP, current TPP configuration would not allow the request to be processed")
	}

	config.UpdateCertificateRequest(req)

	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		if config.CustomAttributeValues[tppAttributeManualCSR] == "0" {
			return fmt.Errorf("Unable to request certificate by local generated CSR when zone configuration is 'Manual Csr' = 0")
		}
		err = req.GeneratePrivateKey()
		if err != nil {
			return err
		}
		err = req.GenerateCSR()
		if err != nil {
			return err
		}
	case certificate.UserProvidedCSR:
		if config.CustomAttributeValues[tppAttributeManualCSR] == "0" {
			return fmt.Errorf("Unable to request certificate with user provided CSR when zone configuration is 'Manual Csr' = 0")
		}
		if len(req.GetCSR()) == 0 {
			return fmt.Errorf("CSR was supposed to be provided by user, but it's empty")
		}

	case certificate.ServiceGeneratedCSR:
	}
	return nil
}

// ConfigWrite replaces all value instances of an attribute on an object, such
// as a Certificate or Discovery objects, with one or more new values.
func (c *Connector) ConfigWrite(req *ConfigWriteRequest) (err error) {
	statusCode, _, body, err := c.request("POST", urlResourceConfigWrite, req)
	if err != nil {
		return fmt.Errorf("%w: %v", verror.ServerTemporaryUnavailableError, err)
	}
	switch statusCode {
	case http.StatusOK:
		return nil
	case http.StatusBadRequest:
		var errorResponse = &struct{ Error string }{}
		err := json.Unmarshal(body, errorResponse)
		if err != nil {
			return fmt.Errorf("%w: failed to decode error message: %s", verror.ServerBadDataResponce, err)
		}
		return fmt.Errorf("%w: can't write config %s", verror.ServerBadDataResponce, errorResponse.Error)
	default:
		return fmt.Errorf("%w: unexpected response status %d: %s", verror.ServerTemporaryUnavailableError, statusCode, string(body))
	}
}

func getPolicyDN(zone string) string {
	modified := zone
	reg := regexp.MustCompile(`^\\VED\\Policy`)
	if reg.FindStringIndex(modified) == nil {
		reg = regexp.MustCompile(`^\\`)
		if reg.FindStringIndex(modified) == nil {
			modified = "\\" + modified
		}
		modified = "\\VED\\Policy" + modified
	}
	return modified
}

func getDeviceDN(zone string, location certificate.Location) string {
	workload := location.Workload
	if workload == "" {
		workload = "Default"
	}
	return getPolicyDN(zone + "\\" + location.Instance + "\\" + workload)
}

func getCertificateDN(zone, cn string) string {
	return getPolicyDN(zone + "\\" + cn)
}

func stripBackSlashes(s string) string {

	var r = regexp.MustCompile(`\\+`)

	result := r.ReplaceAll([]byte(s), []byte("\\"))
	return string(result)
}

func parseConfigResult(httpStatusCode int, httpStatus string, body []byte) (tppData tppPolicyData, err error) {
	tppData = tppPolicyData{}
	switch httpStatusCode {
	case http.StatusOK:
		tppData, err := parseConfigData(body)
		if err != nil {
			return tppData, err
		}
		return tppData, nil
	default:
		return tppData, fmt.Errorf("Unexpected status code on TPP Config Operation. Status: %s", httpStatus)
	}
}

func parseConfigData(b []byte) (data tppPolicyData, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseRequestResult(httpStatusCode int, httpStatus string, body []byte) (string, error) {
	switch httpStatusCode {
	case http.StatusOK, http.StatusCreated:
		reqData, err := parseRequestData(body)
		if err != nil {
			return "", err
		}
		return reqData.CertificateDN, nil
	default:
		return "", fmt.Errorf("Unexpected status code on TPP Certificate Request.\n Status:\n %s. \n Body:\n %s\n", httpStatus, body)
	}
}

func parseRequestData(b []byte) (data certificateRequestResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseRetrieveResult(httpStatusCode int, httpStatus string, body []byte) (certificateRetrieveResponse, error) {
	var retrieveResponse certificateRetrieveResponse
	switch httpStatusCode {
	case http.StatusOK, http.StatusAccepted:
		retrieveResponse, err := parseRetrieveData(body)
		if err != nil {
			return retrieveResponse, err
		}
		return retrieveResponse, nil
	default:
		return retrieveResponse, fmt.Errorf("Unexpected status code on TPP Certificate Retrieval. Status: %s", httpStatus)
	}
}

func parseRetrieveData(b []byte) (data certificateRetrieveResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseRevokeResult(httpStatusCode int, httpStatus string, body []byte) (certificateRevokeResponse, error) {
	var revokeResponse certificateRevokeResponse
	switch httpStatusCode {
	case http.StatusOK, http.StatusAccepted:
		revokeResponse, err := parseRevokeData(body)
		if err != nil {
			return revokeResponse, err
		}
		return revokeResponse, nil
	default:
		return revokeResponse, fmt.Errorf("Unexpected status code on TPP Certificate Revocation. Status: %s", httpStatus)
	}
}

func parseRevokeData(b []byte) (data certificateRevokeResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func parseRenewResult(httpStatusCode int, httpStatus string, body []byte) (resp certificateRenewResponse, err error) {
	resp, err = parseRenewData(body)
	if err != nil {
		return resp, fmt.Errorf("failed to parse certificate renewal response. status: %s", httpStatus)
	}
	return resp, nil
}

func parseRenewData(b []byte) (data certificateRenewResponse, err error) {
	err = json.Unmarshal(b, &data)
	return
}

func newPEMCollectionFromResponse(base64Response string, chainOrder certificate.ChainOption) (*certificate.PEMCollection, error) {
	if base64Response != "" {
		certBytes, err := base64.StdEncoding.DecodeString(base64Response)
		if err != nil {
			return nil, err
		}

		return certificate.PEMCollectionFromBytes(certBytes, chainOrder)
	}
	return nil, nil
}

type _strValue struct {
	Locked bool
	Value  string
}

type serverPolicy struct {
	CertificateAuthority _strValue
	CsrGeneration        _strValue
	KeyGeneration        _strValue
	KeyPair              struct {
		KeyAlgorithm _strValue
		KeySize      struct {
			Locked bool
			Value  int
		}
		EllipticCurve struct {
			Locked bool
			Value  string
		}
	}
	ManagementType _strValue

	PrivateKeyReuseAllowed  bool
	SubjAltNameDnsAllowed   bool
	SubjAltNameEmailAllowed bool
	SubjAltNameIpAllowed    bool
	SubjAltNameUpnAllowed   bool
	SubjAltNameUriAllowed   bool
	Subject                 struct {
		City               _strValue
		Country            _strValue
		Organization       _strValue
		OrganizationalUnit struct {
			Locked bool
			Values []string
		}

		State _strValue
	}
	UniqueSubjectEnforced bool
	WhitelistedDomains    []string
	WildcardsAllowed      bool
}

func (sp serverPolicy) toZoneConfig(zc *endpoint.ZoneConfiguration) {
	zc.Country = sp.Subject.Country.Value
	zc.Organization = sp.Subject.Organization.Value
	zc.OrganizationalUnit = sp.Subject.OrganizationalUnit.Values
	zc.Province = sp.Subject.State.Value
	zc.Locality = sp.Subject.City.Value
	key := endpoint.AllowedKeyConfiguration{}
	err := key.KeyType.Set(sp.KeyPair.KeyAlgorithm.Value)
	if err != nil {
		return
	}
	if sp.KeyPair.KeySize.Value != 0 {
		key.KeySizes = []int{sp.KeyPair.KeySize.Value}
	}
	if sp.KeyPair.EllipticCurve.Value != "" {
		curve := certificate.EllipticCurveNotSet
		err = curve.Set(sp.KeyPair.EllipticCurve.Value)
		if err == nil {
			key.KeyCurves = append(key.KeyCurves, curve)
		}
	}
	zc.KeyConfiguration = &key
}

func (sp serverPolicy) toPolicy() (p endpoint.Policy) {
	addStartEnd := func(s string) string {
		if !strings.HasPrefix(s, "^") {
			s = "^" + s
		}
		if !strings.HasSuffix(s, "$") {
			s = s + "$"
		}
		return s
	}
	escapeOne := func(s string) string {
		return addStartEnd(regexp.QuoteMeta(s))
	}
	escapeArray := func(l []string) []string {
		escaped := make([]string, len(l))
		for i, r := range l {
			escaped[i] = escapeOne(r)
		}
		return escaped
	}
	const allAllowedRegex = ".*"
	if len(sp.WhitelistedDomains) == 0 {
		p.SubjectCNRegexes = []string{allAllowedRegex}
	} else {
		p.SubjectCNRegexes = make([]string, len(sp.WhitelistedDomains))
		for i, d := range sp.WhitelistedDomains {
			if sp.WildcardsAllowed {
				p.SubjectCNRegexes[i] = addStartEnd(`([\p{L}\p{N}-*]+\.)*` + regexp.QuoteMeta(d))
			} else {
				p.SubjectCNRegexes[i] = addStartEnd(`([\p{L}\p{N}-]+\.)*` + regexp.QuoteMeta(d))
			}
		}
	}
	if sp.Subject.OrganizationalUnit.Locked {
		p.SubjectOURegexes = escapeArray(sp.Subject.OrganizationalUnit.Values)
	} else {
		p.SubjectOURegexes = []string{allAllowedRegex}
	}
	if sp.Subject.Organization.Locked {
		p.SubjectORegexes = []string{escapeOne(sp.Subject.Organization.Value)}
	} else {
		p.SubjectORegexes = []string{allAllowedRegex}
	}
	if sp.Subject.City.Locked {
		p.SubjectLRegexes = []string{escapeOne(sp.Subject.City.Value)}
	} else {
		p.SubjectLRegexes = []string{allAllowedRegex}
	}
	if sp.Subject.State.Locked {
		p.SubjectSTRegexes = []string{escapeOne(sp.Subject.State.Value)}
	} else {
		p.SubjectSTRegexes = []string{allAllowedRegex}
	}
	if sp.Subject.Country.Locked {
		p.SubjectCRegexes = []string{escapeOne(sp.Subject.Country.Value)}
	} else {
		p.SubjectCRegexes = []string{allAllowedRegex}
	}
	if sp.SubjAltNameDnsAllowed {
		if len(sp.WhitelistedDomains) == 0 {
			p.DnsSanRegExs = []string{allAllowedRegex}
		} else {
			p.DnsSanRegExs = make([]string, len(sp.WhitelistedDomains))
			for i, d := range sp.WhitelistedDomains {
				if sp.WildcardsAllowed {
					p.DnsSanRegExs[i] = addStartEnd(`([\p{L}\p{N}-*]+\.)*` + regexp.QuoteMeta(d))
				} else {
					p.DnsSanRegExs[i] = addStartEnd(`([\p{L}\p{N}-]+\.)*` + regexp.QuoteMeta(d))
				}
			}
		}
	} else {
		p.DnsSanRegExs = []string{}
	}
	if sp.SubjAltNameIpAllowed {
		p.IpSanRegExs = []string{allAllowedRegex}
	} else {
		p.IpSanRegExs = []string{}
	}
	if sp.SubjAltNameEmailAllowed {
		p.EmailSanRegExs = []string{allAllowedRegex}
	} else {
		p.EmailSanRegExs = []string{}
	}
	if sp.SubjAltNameUriAllowed {
		p.UriSanRegExs = []string{allAllowedRegex}
	} else {
		p.UriSanRegExs = []string{}
	}
	if sp.SubjAltNameUpnAllowed {
		p.UpnSanRegExs = []string{allAllowedRegex}
	} else {
		p.UpnSanRegExs = []string{}
	}
	if sp.KeyPair.KeyAlgorithm.Locked {
		var keyType certificate.KeyType
		if err := keyType.Set(sp.KeyPair.KeyAlgorithm.Value); err != nil {
			panic(err)
		}
		key := endpoint.AllowedKeyConfiguration{KeyType: keyType}
		if keyType == certificate.KeyTypeRSA {
			if sp.KeyPair.KeySize.Locked {
				for _, i := range certificate.AllSupportedKeySizes() {
					if i >= sp.KeyPair.KeySize.Value {
						key.KeySizes = append(key.KeySizes, i)
					}
				}
			} else {
				key.KeySizes = certificate.AllSupportedKeySizes()
			}
		} else {
			var curve certificate.EllipticCurve
			if sp.KeyPair.EllipticCurve.Locked {
				if err := curve.Set(sp.KeyPair.EllipticCurve.Value); err != nil {
					panic(err)
				}
				key.KeyCurves = append(key.KeyCurves, curve)
			} else {
				key.KeyCurves = certificate.AllSupportedCurves()
			}

		}
		p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, key)
	} else {
		var ks []int
		for _, s := range certificate.AllSupportedKeySizes() {
			if !sp.KeyPair.KeySize.Locked || s >= sp.KeyPair.KeySize.Value {
				ks = append(ks, s)
			}
		}
		p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, endpoint.AllowedKeyConfiguration{
			KeyType: certificate.KeyTypeRSA, KeySizes: ks,
		})
		if sp.KeyPair.EllipticCurve.Locked {
			var curve certificate.EllipticCurve
			if err := curve.Set(sp.KeyPair.EllipticCurve.Value); err != nil {
				panic(err)
			}
			p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, endpoint.AllowedKeyConfiguration{
				KeyType: certificate.KeyTypeECDSA, KeyCurves: []certificate.EllipticCurve{curve},
			})
		} else {
			p.AllowedKeyConfigurations = append(p.AllowedKeyConfigurations, endpoint.AllowedKeyConfiguration{
				KeyType: certificate.KeyTypeECDSA, KeyCurves: certificate.AllSupportedCurves(),
			})
		}
	}
	p.AllowWildcards = sp.WildcardsAllowed
	p.AllowKeyReuse = sp.PrivateKeyReuseAllowed
	return
}
