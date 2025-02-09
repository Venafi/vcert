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

package cloud

import (
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-http-utils/headers"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

type apiKey struct {
	Key                     string    `json:"key,omitempty"`
	UserID                  string    `json:"userId,omitempty"`
	Username                string    `json:"username,omitempty"`
	CompanyID               string    `json:"companyId,omitempty"`
	APITypes                []string  `json:"apitypes,omitempty"`
	APIVersion              string    `json:"apiVersion,omitempty"`
	APIKeyStatus            string    `json:"apiKeyStatus,omitempty"`
	CreationDateString      string    `json:"creationDate,omitempty"`
	CreationDate            time.Time `json:"-"`
	ValidityStartDateString string    `json:"validityStartDate,omitempty"`
	ValidityStartDate       time.Time `json:"-"`
	ValidityEndDateString   string    `json:"validityEndDate,omitempty"`
	ValidityEndDate         time.Time `json:"-"`
}

type userDetails struct {
	User    *user    `json:"user,omitempty"`
	Company *company `json:"company,omitempty"`
	APIKey  *apiKey  `json:"apiKey,omitempty"`
}

type OwnerType int64

const (
	UserType OwnerType = iota
	TeamType
)

func (o OwnerType) String() string {
	switch o {
	case UserType:
		return "USER"
	case TeamType:
		return "TEAM"
	}
	return "unknown"
}

type certificateRequestResponse struct {
	CertificateRequests []certificateRequestResponseData `json:"certificateRequests,omitempty"`
}

type certificateRequestResponseData struct {
	ID                 string    `json:"id,omitempty"`
	ApplicationId      string    `json:"applicationId,omitempty"`
	TemplateId         string    `json:"certificateIssuingTemplateId,omitempty"`
	Status             string    `json:"status,omitempty"`
	SubjectDN          string    `json:"subjectDN,omitempty"`
	CreationDateString string    `json:"creationDate,omitempty"`
	CreationDate       time.Time `json:"-"`
	CertificateIds     []string  `json:"certificateIds,omitempty"`
}

type certificateRequestClientInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type certificateRetireResponse struct {
	Count        int           `count:"id,omitempty"`
	Certificates []Certificate `json:"certificates,omitempty"`
}

type certificateRequest struct {
	CSR                      string                       `json:"certificateSigningRequest,omitempty"`
	ApplicationId            string                       `json:"applicationId,omitempty"`
	TemplateId               string                       `json:"certificateIssuingTemplateId,omitempty"`
	CertificateOwnerUserId   string                       `json:"certificateOwnerUserId,omitempty"`
	ExistingCertificateId    string                       `json:"existingCertificateId,omitempty"`
	ApiClientInformation     certificateRequestClientInfo `json:"apiClientInformation,omitempty"`
	CertificateUsageMetadata []certificateUsageMetadata   `json:"certificateUsageMetadata,omitempty"`
	ReuseCSR                 bool                         `json:"reuseCSR,omitempty"`
	ValidityPeriod           string                       `json:"validityPeriod,omitempty"`
	IsVaaSGenerated          bool                         `json:"isVaaSGenerated,omitempty"`
	CsrAttributes            CsrAttributes                `json:"csrAttributes,omitempty"`
	ApplicationServerTypeId  string                       `json:"applicationServerTypeId,omitempty"`
}

type certificateRetireRequest struct {
	CertificateIds []string `json:"certificateIds,omitempty"`
	AddToBlocklist bool     `json:"addToBlocklist,omitempty"`
}

type CsrAttributes struct {
	CommonName                    *string                        `json:"commonName,omitempty"`
	Organization                  *string                        `json:"organization,omitempty"`
	OrganizationalUnits           []string                       `json:"organizationalUnits,omitempty"`
	Locality                      *string                        `json:"locality,omitempty"`
	State                         *string                        `json:"state,omitempty"`
	Country                       *string                        `json:"country,omitempty"`
	SubjectAlternativeNamesByType *SubjectAlternativeNamesByType `json:"subjectAlternativeNamesByType,omitempty"`
	KeyTypeParameters             *KeyTypeParameters             `json:"keyTypeParameters,omitempty"`
}

type KeyTypeParameters struct {
	KeyType   string  `json:"keyType,omitempty"`
	KeyLength *int    `json:"keyLength,omitempty"`
	KeyCurve  *string `json:"keyCurve,omitempty"`
}

type SubjectAlternativeNamesByType struct {
	DnsNames                   []string `json:"dnsNames,omitempty"`
	IpAddresses                []string `json:"ipAddresses,omitempty"`
	Rfc822Names                []string `json:"rfc822Names,omitempty"`
	UniformResourceIdentifiers []string `json:"uniformResourceIdentifiers,omitempty"`
}

type KeyStoreRequest struct {
	ExportFormat                  string `json:"exportFormat,omitempty"`
	EncryptedPrivateKeyPassphrase string `json:"encryptedPrivateKeyPassphrase"`
	EncryptedKeystorePassphrase   string `json:"encryptedKeystorePassphrase"`
	CertificateLabel              string `json:"certificateLabel"`
}

type EdgeEncryptionKey struct {
	Key string `json:"key,omitempty"`
}

type certificateStatus struct {
	Id                        string                            `json:"id,omitempty"`
	CertificateIdsList        []string                          `json:"certificateIds,omitempty"`
	ApplicationId             string                            `json:"applicationId,omitempty"`
	TemplateId                string                            `json:"certificateIssuingTemplateId,omitempty"`
	Status                    string                            `json:"status,omitempty"`
	ErrorInformation          CertificateStatusErrorInformation `json:"errorInformation,omitempty"`
	CreationDate              string                            `json:"creationDate,omitempty"`
	ModificationDate          string                            `json:"modificationDate,omitempty"`
	CertificateSigningRequest string                            `json:"certificateSigningRequest,omitempty"`
	SubjectDN                 string                            `json:"subjectDN,omitempty"`
}

type CertificateStatusErrorInformation struct {
	Type    string   `json:"type,omitempty"`
	Code    int      `json:"code,omitempty"`
	Message string   `json:"message,omitempty"`
	Args    []string `json:"args,omitempty"`
}

type apiClientInformation struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type certificateUsageMetadata struct {
	AppName            string `json:"appName,omitempty"`
	NodeName           string `json:"nodeName,omitempty"`
	AutomationMetadata string `json:"automationMetadata,omitempty"`
}

type importRequest struct {
	Certificates []importRequestCertInfo `json:"certificates"`
}

type importRequestCertInfo struct {
	Certificate              string                     `json:"certificate"`
	IssuerCertificates       []string                   `json:"issuerCertificates,omitempty"`
	ApplicationIds           []string                   `json:"applicationIds"`
	ApiClientInformation     apiClientInformation       `json:"apiClientInformation,omitempty"`
	CertificateUsageMetadata []certificateUsageMetadata `json:"certificateUsageMetadata,omitempty"`
}

type importResponseCertInfo struct {
	Id                      string               `json:"id"`
	ManagedCertificateId    string               `json:"managedCertificateId"`
	CompanyId               string               `json:"companyId"`
	Fingerprint             string               `json:"fingerprint"`
	CertificateSource       string               `json:"certificateSource"`
	OwnerUserId             string               `json:"ownerUserId"`
	IssuanceZoneId          string               `json:"issuanceZoneId"`
	ValidityStartDateString string               `json:"validityStartDate"`
	ValidityStartDate       time.Time            `json:"-"`
	ValidityEndDateString   string               `json:"validityEndDate"`
	ValidityEndDate         time.Time            `json:"-"`
	ApiClientInformation    apiClientInformation `json:"apiClientInformation,omitempty"`
}

type importResponse struct {
	CertificateInformations []importResponseCertInfo `json:"certificateInformations"`
}

type ApplicationDetails struct {
	ApplicationId             string               `json:"id,omitempty"`
	CitAliasToIdMap           map[string]string    `json:"certificateIssuingTemplateAliasIdMap,omitempty"`
	CompanyId                 string               `json:"companyId,omitempty"`
	Name                      string               `json:"name,omitempty"`
	Description               string               `json:"description,omitempty"`
	OwnerIdType               []policy.OwnerIdType `json:"ownerIdsAndTypes,omitempty"`
	InternalFqDns             []string             `json:"internalFqDns,omitempty"`
	ExternalIpRanges          []string             `json:"externalIpRanges,omitempty"`
	InternalIpRanges          []string             `json:"internalIpRanges,omitempty"`
	InternalPorts             []string             `json:"internalPorts,omitempty"`
	FullyQualifiedDomainNames []string             `json:"fullyQualifiedDomainNames,omitempty"`
	IpRanges                  []string             `json:"ipRanges,omitempty"`
	Ports                     []string             `json:"ports,omitempty"`
	FqDns                     []string             `json:"fqDns,omitempty"`
}

// GenerateRequest generates a CertificateRequest based on the zone configuration, and returns the request along with the private key.
func (c *Connector) GenerateRequest(config *endpoint.ZoneConfiguration, req *certificate.Request) (err error) {
	switch req.CsrOrigin {
	case certificate.LocalGeneratedCSR:
		if config == nil {
			config, err = c.ReadZoneConfiguration()
			if err != nil {
				return fmt.Errorf("could not read zone configuration: %w", err)
			}
		}
		config.UpdateCertificateRequest(req)
		if err := req.GeneratePrivateKey(); err != nil {
			return err
		}
		err = req.GenerateCSR()
		return
	case certificate.UserProvidedCSR:
		if len(req.GetCSR()) == 0 {
			return fmt.Errorf("%w: CSR was supposed to be provided by user, but it's empty", verror.UserDataError)
		}
		return nil

	case certificate.ServiceGeneratedCSR:
		if req.KeyType == certificate.KeyTypeED25519 {
			return fmt.Errorf("%w: ED25519 keys are not yet supported for Service Generated CSR", verror.UserDataError)
		}
		return nil

	default:
		return fmt.Errorf("%w: unrecognised req.CsrOrigin %v", verror.UserDataError, req.CsrOrigin)
	}
}

func (c *Connector) getURL(resource urlResource) string {
	return fmt.Sprintf("%s%s", c.baseURL, resource)
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
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	tlsConfig := http.DefaultTransport.(*http.Transport).TLSClientConfig
	/* #nosec */
	if c.trust != nil {
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.RootCAs = c.trust
		netTransport.TLSClientConfig = tlsConfig
	}

	c.client = &http.Client{
		Timeout:   time.Second * 30,
		Transport: netTransport,
	}
	return c.client
}

func (c *Connector) request(method string, url string, data interface{}, authNotRequired ...bool) (statusCode int, statusText string, body []byte, err error) {
	if c.accessToken == "" && c.apiKey == "" {
		if !(len(authNotRequired) == 1 && authNotRequired[0]) {
			err = fmt.Errorf("%w: must be autheticated to make requests to TLSPC API", verror.VcertError)
			return
		}
	}

	var payload io.Reader
	var b []byte
	if method == http.MethodPost || method == http.MethodPut {
		b, _ = json.Marshal(data)
		payload = bytes.NewReader(b)
	}

	r, err := http.NewRequest(method, url, payload)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.VcertError, err)
		return
	}

	r.Header.Set(headers.UserAgent, c.userAgent)
	if c.accessToken != "" {
		r.Header.Add(headers.Authorization, fmt.Sprintf("%s %s", util.OauthTokenType, c.accessToken))
	} else if c.apiKey != "" {
		r.Header.Add(util.HeaderTpplApikey, c.apiKey)
	}

	if method == http.MethodPost || method == http.MethodPut {
		r.Header.Add(headers.Accept, "application/json")
		r.Header.Add(headers.ContentType, "application/json")
	} else {
		r.Header.Add(headers.Accept, "*/*")
	}
	r.Header.Add(headers.CacheControl, "no-cache")

	var httpClient = c.getHTTPClient()

	res, err := httpClient.Do(r)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.ServerUnavailableError, err)
		return
	}
	statusCode = res.StatusCode
	statusText = res.Status

	defer res.Body.Close()
	body, err = io.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	if c.verbose {
		log.Printf("Got %s status for %s %s\n", statusText, method, url)
	}
	return
}

func parseUserDetailsResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*userDetails, error) {
	if httpStatusCode == expectedStatusCode {
		return parseJSON[userDetails](body, verror.ServerError)
	}
	respErrors, err := parseResponseErrors(body)
	if err != nil {
		// Parsing the error failed, return the original error
		bodyText := strings.TrimSpace(string(body))
		if bodyText == "" {
			return nil, fmt.Errorf("%w: %s", verror.ServerError, httpStatus)
		}

		return nil, fmt.Errorf("%w: %s, %s", verror.ServerError, httpStatus, bodyText)
	}
	respError := fmt.Sprintf("unexpected status code on Venafi Cloud registration. Status: %s\n", httpStatus)
	for _, e := range respErrors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseUserDetailsResultFromPOST(httpStatusCode int, httpStatus string, body []byte) (*userDetails, error) {
	if httpStatusCode == http.StatusCreated || httpStatusCode == http.StatusAccepted {
		return parseJSON[userDetails](body, verror.ServerError)
	}
	respErrors, err := parseResponseErrors(body)
	if err != nil {
		return nil, err // parseResponseErrors always return verror.ServerError
	}
	respError := fmt.Sprintf("unexpected status code on Venafi Cloud registration. Status: %s\n", httpStatus)
	for _, e := range respErrors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseJSON[T any](b []byte, errorMessage error) (*T, error) {
	var data T
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errorMessage, err)
	}
	return &data, nil
}

func parseUserByIdResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*user, error) {
	if httpStatusCode == expectedStatusCode {
		return parseJSON[user](body, verror.ServerError)
	}
	respErrors, err := parseResponseErrors(body)
	if err != nil {
		return nil, err // parseResponseErrors always return verror.ServerError
	}
	respError := fmt.Sprintf("unexpected status code on retrieval of user by ID. Status: %s\n", httpStatus)
	for _, e := range respErrors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseUsersByNameResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*users, error) {
	if httpStatusCode == expectedStatusCode {
		return parseJSON[users](body, verror.ServerError)
	}
	respErrors, err := parseResponseErrors(body)
	if err != nil {
		return nil, err // parseResponseErrors always return verror.ServerError
	}
	respError := fmt.Sprintf("unexpected status code on retrieval of users by name. Status: %s\n", httpStatus)
	for _, e := range respErrors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseCertByIdResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*VenafiCertificate, error) {
	if httpStatusCode == expectedStatusCode {
		return parseJSON[VenafiCertificate](body, verror.ServerError)
	}
	respErrors, err := parseResponseErrors(body)
	if err != nil {
		return nil, err // parseResponseErrors always return verror.ServerError
	}
	respError := fmt.Sprintf("unexpected status code on retrieval of certificate by ID. Status: %s\n", httpStatus)
	for _, e := range respErrors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseTeamsResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*teams, error) {
	if httpStatusCode == expectedStatusCode {
		return parseJSON[teams](body, verror.ServerError)
	}
	respErrors, err := parseResponseErrors(body)
	if err != nil {
		return nil, err // parseResponseErrors always return verror.ServerError
	}
	respError := fmt.Sprintf("unexpected status code on retrieval of teams. Status: %s\n", httpStatus)
	for _, e := range respErrors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseZoneConfigurationResult(httpStatusCode int, httpStatus string, body []byte) (*zone, error) {
	switch httpStatusCode {
	case http.StatusOK:
		return parseJSON[zone](body, verror.ServerError)
	case http.StatusBadRequest, http.StatusNotFound:
		return nil, verror.ZoneNotFoundError
	default:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud zone read. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			if e.Code == 10051 {
				return nil, verror.ZoneNotFoundError
			}
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
	}
}

func parseCertificateTemplateResult(httpStatusCode int, httpStatus string, body []byte) (*certificateTemplate, error) {
	switch httpStatusCode {
	case http.StatusOK:
		return parseJSON[certificateTemplate](body, verror.ServerError)
	case http.StatusBadRequest:
		return nil, verror.ZoneNotFoundError
	case http.StatusUnauthorized:
		return nil, verror.UnauthorizedError
	default:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud zone read. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			if e.Code == 10051 {
				return nil, verror.ZoneNotFoundError
			}
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
	}
}

func parseCertificateRequestResult(httpStatusCode int, httpStatus string, body []byte) (*certificateRequestResponse, error) {
	switch httpStatusCode {
	case http.StatusCreated:
		return parseJSON[certificateRequestResponse](body, verror.ServerError)
	default:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud zone read. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
	}
}

func checkCertificateRetireResults(httpStatusCode int, httpStatus string, body []byte) error {
	switch httpStatusCode {
	case 200:
		resp, err := parseJSON[certificateRetireResponse](body, verror.ServerError)
		if err != nil {
			return err
		} else if resp.Count == 0 {
			return fmt.Errorf("Invalid thumbprint or certificate ID. No certificates were retired")
		} else {
			return nil
		}
	default:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud zone read. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return fmt.Errorf("%w: %v", verror.ServerError, respError)
	}
}

func newPEMCollectionFromResponse(data []byte, chainOrder certificate.ChainOption) (*certificate.PEMCollection, error) {
	return certificate.PEMCollectionFromBytes(data, chainOrder)
}

func certThumbprint(asn1 []byte) string {
	h := sha1.Sum(asn1)
	return strings.ToUpper(fmt.Sprintf("%x", h))
}

func parseApplicationDetailsResult(httpStatusCode int, httpStatus string, body []byte) (*ApplicationDetails, error) {
	switch httpStatusCode {
	case http.StatusOK:
		return parseJSON[ApplicationDetails](body, verror.ServerError)
	case http.StatusBadRequest:
		return nil, verror.ApplicationNotFoundError
	case http.StatusUnauthorized:
		return nil, fmt.Errorf("%w: %s", verror.ServerError, httpStatus)
	default:
		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud application read. Status: %s\n", httpStatus)
		for _, e := range respErrors {
			if e.Code == 10051 {
				return nil, verror.ApplicationNotFoundError
			}
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
	}
}

type cloudZone struct {
	zone          string
	appName       string
	templateAlias string
}

func (z cloudZone) String() string {
	return z.zone
}

func (z *cloudZone) getApplicationName() string {
	if z.appName == "" {
		err := z.parseZone()
		if err != nil {
			return ""
		}
	}
	return z.appName
}

func (z *cloudZone) getTemplateAlias() string {
	if z.templateAlias == "" {
		err := z.parseZone()
		if err != nil {
			return ""
		}
	}
	return z.templateAlias
}

func (z *cloudZone) parseZone() error {
	if z.zone == "" {
		return fmt.Errorf("zone not specified")
	}

	segments := strings.Split(z.zone, "\\")
	if len(segments) != 2 {
		return fmt.Errorf("invalid zone format")
	}

	z.appName = segments[0]
	z.templateAlias = segments[1]

	return nil
}

func createAppUpdateRequest(applicationDetails *ApplicationDetails) policy.Application {
	request := policy.Application{
		OwnerIdsAndTypes:                     applicationDetails.OwnerIdType,
		Name:                                 applicationDetails.Name,
		Description:                          applicationDetails.Description,
		Fqdns:                                applicationDetails.FqDns,
		InternalFqdns:                        applicationDetails.InternalFqDns,
		InternalIpRanges:                     applicationDetails.InternalIpRanges,
		ExternalIpRanges:                     applicationDetails.ExternalIpRanges,
		InternalPorts:                        applicationDetails.InternalPorts,
		FullyQualifiedDomainNames:            applicationDetails.FullyQualifiedDomainNames,
		IpRanges:                             applicationDetails.IpRanges,
		Ports:                                applicationDetails.Ports,
		CertificateIssuingTemplateAliasIdMap: applicationDetails.CitAliasToIdMap,
	}

	return request
}

func getSAN(p *policy.Policy) *policy.SubjectAltNames {
	if p == nil || p.SubjectAltNames == nil {
		san := policy.SubjectAltNames{}
		p.SubjectAltNames = &san
		return &san
	}
	return p.SubjectAltNames
}

func buildPolicySpecification(cit *certificateTemplate, info *policy.CertificateAuthorityInfo, removeRegex bool) *policy.PolicySpecification {
	if cit == nil {
		return nil
	}

	var ps policy.PolicySpecification

	var pol policy.Policy

	if len(cit.SubjectCNRegexes) > 0 {
		if removeRegex {
			pol.Domains = policy.RemoveRegex(cit.SubjectCNRegexes)
		} else {
			pol.Domains = cit.SubjectCNRegexes
		}
	}

	wildCard := isWildCard(cit.SubjectCNRegexes)
	pol.WildcardAllowed = &wildCard

	if len(cit.SANRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		subjectAlt.DnsAllowed = util.GetBooleanRef(true)
	}

	if len(cit.SanRfc822NameRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		subjectAlt.EmailAllowed = util.GetBooleanRef(true)
	}

	if len(cit.SanUniformResourceIdentifierRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		protocols := make([]string, 0)
		for _, val := range cit.SanUniformResourceIdentifierRegexes {
			index := strings.Index(val, ")://")
			subStr := val[1:index]
			currProtocols := strings.Split(subStr, "|")
			for _, currentProtocol := range currProtocols {
				if len(protocols) == 0 {
					protocols = append(protocols, currentProtocol)
				} else {
					if !contains(protocols, currentProtocol) {
						protocols = append(protocols, currentProtocol)
					}
				}
			}
		}
		subjectAlt.UriProtocols = protocols
		subjectAlt.UriAllowed = util.GetBooleanRef(true)
	}

	if len(cit.SanIpAddressRegexes) > 0 {
		subjectAlt := getSAN(&pol)
		subjectAlt.IpAllowed = util.GetBooleanRef(true)
	}

	// ps.Policy.WildcardAllowed is pending.
	if cit.ValidityPeriod != "" {
		//they have the format P#D
		days := cit.ValidityPeriod[1 : len(cit.ValidityPeriod)-1]
		intDays, _ := strconv.ParseInt(days, 10, 32)
		//ok we have a 32 bits int but we need to convert it just into a "int"
		intVal := int(intDays)
		pol.MaxValidDays = &intVal
	}
	if info != nil {
		ca := fmt.Sprint(info.CAType, "\\", info.CAAccountKey, "\\", info.VendorProductName)
		pol.CertificateAuthority = &ca
	}

	//subject.
	var subject policy.Subject

	if len(cit.SubjectORegexes) > 0 {
		subject.Orgs = cit.SubjectORegexes
	} else if cit.SubjectORegexes == nil {
		subject.Orgs = []string{""}
	}

	if len(cit.SubjectOURegexes) > 0 {
		subject.OrgUnits = cit.SubjectOURegexes
	} else if cit.SubjectOURegexes == nil {
		subject.OrgUnits = []string{""}
	}

	if len(cit.SubjectLRegexes) > 0 {
		subject.Localities = cit.SubjectLRegexes
	} else if cit.SubjectLRegexes == nil {
		subject.Localities = []string{""}
	}

	if len(cit.SubjectSTRegexes) > 0 {
		subject.States = cit.SubjectSTRegexes
	} else if cit.SubjectSTRegexes == nil {
		subject.States = []string{""}
	}

	if len(cit.SubjectCValues) > 0 {
		subject.Countries = cit.SubjectCValues
	} else if cit.SubjectCValues == nil {
		subject.Countries = []string{""}
	}

	pol.Subject = &subject

	//key pair
	var keyPair policy.KeyPair
	shouldCreateKeyPair := false
	if len(cit.KeyTypes) > 0 {
		var keyTypes []string
		var keySizes []int
		var ellipticCurves []string

		for _, allowedKT := range cit.KeyTypes {
			keyType := string(allowedKT.KeyType)
			keyLengths := allowedKT.KeyLengths
			ecKeys := allowedKT.KeyCurves

			keyTypes = append(keyTypes, keyType)

			if len(keyLengths) > 0 {
				keySizes = append(keySizes, keyLengths...)
			}

			if len(ecKeys) > 0 {
				ellipticCurves = append(ellipticCurves, ecKeys...)
			}

		}
		shouldCreateKeyPair = true
		keyPair.KeyTypes = keyTypes
		if len(keySizes) > 0 {
			keyPair.RsaKeySizes = keySizes
		}

		if len(ellipticCurves) > 0 {
			keyPair.EllipticCurves = ellipticCurves
		}
	}

	if cit.KeyGeneratedByVenafiAllowed && cit.CsrUploadAllowed {
		keyPair.ServiceGenerated = nil
	} else if cit.KeyGeneratedByVenafiAllowed {
		keyPair.ServiceGenerated = &cit.KeyGeneratedByVenafiAllowed
		shouldCreateKeyPair = true
	} else if cit.CsrUploadAllowed {
		falseVal := false
		keyPair.ServiceGenerated = &falseVal
		shouldCreateKeyPair = true
	}

	if shouldCreateKeyPair {
		pol.KeyPair = &keyPair
		pol.KeyPair.ReuseAllowed = &cit.KeyReuse
	}

	ps.Policy = &pol

	//build defaults.
	var defaultSub policy.DefaultSubject
	shouldCreateDeFaultSub := false
	if cit.RecommendedSettings.SubjectOValue != "" {
		defaultSub.Org = &cit.RecommendedSettings.SubjectOValue
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectOUValue != "" {
		defaultSub.OrgUnits = []string{cit.RecommendedSettings.SubjectOUValue}
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectCValue != "" {
		defaultSub.Country = &cit.RecommendedSettings.SubjectCValue
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectSTValue != "" {
		defaultSub.State = &cit.RecommendedSettings.SubjectSTValue
		shouldCreateDeFaultSub = true
	}

	if cit.RecommendedSettings.SubjectLValue != "" {
		defaultSub.Locality = &cit.RecommendedSettings.SubjectLValue
		shouldCreateDeFaultSub = true
	}

	if shouldCreateDeFaultSub {
		if ps.Default == nil {
			ps.Default = &policy.Default{}
		}
		ps.Default.Subject = &defaultSub
	}

	//default key type
	var defaultKP policy.DefaultKeyPair
	shouldCreateDefaultKeyPAir := false

	if cit.RecommendedSettings.Key.Type != "" {
		defaultKP.KeyType = &cit.RecommendedSettings.Key.Type
		shouldCreateDefaultKeyPAir = true
	}

	if cit.RecommendedSettings.Key.Length > 0 {
		defaultKP.RsaKeySize = &cit.RecommendedSettings.Key.Length
		shouldCreateDefaultKeyPAir = true
	}

	if cit.RecommendedSettings.Key.Curve != "" {
		defaultKP.EllipticCurve = &cit.RecommendedSettings.Key.Curve
		shouldCreateDefaultKeyPAir = true
	}

	if shouldCreateDefaultKeyPAir {
		if ps.Default == nil {
			ps.Default = &policy.Default{}
		}
		ps.Default.KeyPair = &defaultKP
	}

	return &ps
}

func contains(values []string, toSearch string) bool {
	copiedValues := make([]string, len(values))
	copy(copiedValues, values)
	sort.Strings(copiedValues)

	return binarySearch(copiedValues, toSearch) >= 0
}

func binarySearch(values []string, toSearch string) int {
	length := len(values) - 1
	minimum := 0
	for minimum <= length {
		mid := length - (length-minimum)/2
		if strings.Compare(toSearch, values[mid]) > 0 {
			minimum = mid + 1
		} else if strings.Compare(toSearch, values[mid]) < 0 {
			length = mid - 1
		} else {
			return mid
		}
	}
	return -1
}

func parseCitResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*certificateTemplate, error) {
	if httpStatusCode == expectedStatusCode {
		return parseCitDetailsData(body, httpStatusCode)
	}
	respErrors, err := parseResponseErrors(body)
	if err != nil {
		return nil, err // parseResponseErrors always return verror.ServerError
	}
	respError := fmt.Sprintf("unexpected status code on Venafi Cloud registration. Status: %s\n", httpStatus)
	for _, e := range respErrors {
		respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
	}
	return nil, fmt.Errorf("%w: %v", verror.ServerError, respError)
}

func parseCitDetailsData(b []byte, status int) (*certificateTemplate, error) {

	var cits CertificateTemplates
	var cit certificateTemplate

	if status == http.StatusOK { //update case
		err := json.Unmarshal(b, &cit)

		if err != nil {
			return nil, err
		}
	} else { //create case
		err := json.Unmarshal(b, &cits)

		if err != nil {
			return nil, err
		}

		//we just get the cit we created/updated
		cit = cits.CertificateTemplates[0]
	}

	return &cit, nil
}

func isWildCard(cnRegex []string) bool {
	if len(cnRegex) > 0 {
		for _, val := range cnRegex {
			if !(strings.HasPrefix(val, "[*a")) {
				return false
			}
		}
		return true
	}
	return false
}

func getServiceAccountTokenURL(rawURL string) (string, error) {
	// removing trailing slash from util.NormalizeURL function
	_, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return "", fmt.Errorf("token url error: %w", err)
	}

	return rawURL, nil
}
