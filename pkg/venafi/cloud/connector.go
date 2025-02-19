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

package cloud

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	netUrl "net/url"
	"strings"
	"time"

	"github.com/go-http-utils/headers"
	"golang.org/x/crypto/nacl/box"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/verror"
	"github.com/Venafi/vcert/v5/pkg/webclient/cloudproviders"
	"github.com/Venafi/vcert/v5/pkg/webclient/notificationservice"
)

type urlResource string

const (
	apiURL                                        = "api.venafi.cloud/"
	apiVersion                                    = "v1/"
	basePath                                      = "outagedetection/" + apiVersion
	urlResourceUserAccounts           urlResource = apiVersion + "useraccounts"
	urlResourceCertificateRequests    urlResource = basePath + "certificaterequests"
	urlResourceCertificatesRetirement             = urlResourceCertificates + "/retirement"
	urlResourceCertificateStatus                  = urlResourceCertificateRequests + "/%s"
	urlResourceCertificates           urlResource = basePath + "certificates"
	urlResourceCertificateByID                    = urlResourceCertificates + "/%s"
	urlResourceCertificateRetrievePem             = urlResourceCertificates + "/%s/contents"
	urlResourceCertificateSearch      urlResource = basePath + "certificatesearch"
	urlResourceTemplate               urlResource = basePath + "applications/%s/certificateissuingtemplates/%s"
	urlAppDetailsByName               urlResource = basePath + "applications/name/%s"
	urlIssuingTemplate                urlResource = apiVersion + "certificateissuingtemplates"
	urlAppRoot                        urlResource = basePath + "applications"
	urlCAAccounts                     urlResource = apiVersion + "certificateauthorities/%s/accounts"
	urlCAAccountDetails                           = urlCAAccounts + "/%s"
	urlResourceCertificateKS                      = urlResourceCertificates + "/%s/keystore"
	urlDekPublicKey                   urlResource = apiVersion + "edgeencryptionkeys/%s"
	urlUsers                          urlResource = apiVersion + "users"
	urlUserById                                   = urlUsers + "/%s"
	urlUsersByName                                = urlUsers + "/username/%s"
	urlTeams                          urlResource = apiVersion + "teams"
	urlCertificateDetails                         = basePath + "certificates/%s"
	urlGraphql                                    = "graphql"

	defaultAppName = "Default"
	oauthTokenType = "Bearer"
)

type condorChainOption string

const (
	condorChainOptionRootFirst condorChainOption = "ROOT_FIRST"
	condorChainOptionRootLast  condorChainOption = "EE_FIRST"
)

// Connector contains the base data needed to communicate with the Venafi Cloud servers
type Connector struct {
	baseURL               string
	apiKey                string
	accessToken           string
	verbose               bool
	trust                 *x509.CertPool
	zone                  cloudZone
	client                *http.Client
	userAgent             string
	cloudProvidersClient  *cloudproviders.CloudProvidersClient
	notificationSvcClient *notificationservice.NotificationServiceClient
}

// NewConnector creates a new Venafi Cloud Connector object used to communicate with Venafi Cloud
func NewConnector(url string, zone string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	cZone := cloudZone{zone: zone}
	c := Connector{verbose: verbose, trust: trust, zone: cZone, userAgent: util.DefaultUserAgent}

	var err error
	c.baseURL, err = normalizeURL(url)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeCloud
}

func (c *Connector) SetZone(z string) {
	cZone := cloudZone{zone: z}
	c.zone = cZone
}

func (c *Connector) SetUserAgent(userAgent string) {
	c.userAgent = userAgent
}

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

// Ping attempts to connect to the Venafi Cloud API and returns an error if it cannot
func (c *Connector) Ping() (err error) {
	return nil
}

// Authenticate sets the authentication credentials for the Venafi Cloud API.
// It will send a request to the API to verify the credentials are correct.
func (c *Connector) Authenticate(auth *endpoint.Authentication) error {
	if err := c.SetAuthentication(auth); err != nil {
		return err
	}

	if _, err := c.getUserDetails(); err != nil {
		return fmt.Errorf("%w: %s", verror.AuthError, err)
	}

	return nil
}

// SetAuthentication sets the authentication credentials for the Venafi Cloud API.
func (c *Connector) SetAuthentication(auth *endpoint.Authentication) (err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%w: %s", verror.AuthError, err)
		}
	}()

	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}

	if auth.AccessToken != "" {
		// 1. Access token. Assign it to connector
		c.accessToken = auth.AccessToken
	} else if auth.TokenURL != "" && auth.ExternalJWT != "" {
		// 2. JWT and token URL. use it to request new access token
		tokenResponse, err := c.GetAccessToken(auth)
		if err != nil {
			return err
		}
		c.accessToken = tokenResponse.AccessToken
	} else if auth.APIKey != "" {
		// 3. API key. Assign it to connector
		c.apiKey = auth.APIKey
	}

	// Initialize clients
	c.cloudProvidersClient = cloudproviders.NewCloudProvidersClient(c.getURL(urlGraphql), c.getGraphqlHTTPClient())
	c.notificationSvcClient = notificationservice.NewNotificationServiceClient(c.baseURL, c.accessToken, c.apiKey)

	return nil
}

func (c *Connector) ReadPolicyConfiguration() (policy *endpoint.Policy, err error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")

	}
	config, err := c.ReadZoneConfiguration()
	if err != nil {
		return nil, err
	}
	policy = &config.Policy
	return
}

// ReadZoneConfiguration reads the Zone information needed for generating and requesting a certificate from Venafi Cloud
func (c *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

	var template *certificateTemplate
	var statusCode int

	// to fully support the "headless registration" use case...
	// if application does not exist and is for the default CIT, create the application
	citAlias := c.zone.getTemplateAlias()
	if citAlias == "Default" {
		appName := c.zone.getApplicationName()
		_, statusCode, err = c.getAppDetailsByName(appName)
		if err != nil && statusCode == 404 {
			log.Printf("creating application %s for issuing template %s", appName, citAlias)

			ps := policy.PolicySpecification{}
			template, err = getCit(c, citAlias)
			if err != nil {
				return
			}
			_, err = c.createApplication(appName, &ps, template)
			if err != nil {
				return
			}
		}
	}
	if template == nil {
		template, err = c.getTemplateByID()
		if err != nil {
			return
		}
	}
	config = getZoneConfiguration(template)
	return config, nil
}

// GetZonesByParent returns a list of valid zones for a VaaS application specified by parent
func (c *Connector) GetZonesByParent(parent string) ([]string, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

	var zones []string
	appDetails, _, err := c.getAppDetailsByName(parent)
	if err != nil {
		return nil, err
	}

	for citAlias := range appDetails.CitAliasToIdMap {
		zone := fmt.Sprintf("%s\\%s", parent, citAlias)
		zones = append(zones, zone)
	}
	return zones, nil
}

// ResetCertificate resets the state of a certificate.
func (c *Connector) ResetCertificate(_ *certificate.Request, _ bool) (err error) {
	return fmt.Errorf("not supported by endpoint")
}

// RequestCertificate submits the CSR to the Venafi Cloud API for processing
func (c *Connector) RequestCertificate(req *certificate.Request) (requestID string, err error) {
	if !c.isAuthenticated() {
		return "", fmt.Errorf("must be autheticated to request a certificate")
	}

	url := c.getURL(urlResourceCertificateRequests)
	cloudReq, err := c.getCloudRequest(req)
	if err != nil {
		return "", err
	}

	statusCode, status, body, err := c.request("POST", url, cloudReq)

	if err != nil {
		return "", err
	}
	cr, err := parseCertificateRequestResult(statusCode, status, body)
	if err != nil {
		return "", err
	}
	requestID = cr.CertificateRequests[0].ID
	req.PickupID = requestID
	return requestID, nil
}

// RetrieveCertificate retrieves the certificate for the specified ID
func (c *Connector) RetrieveCertificate(req *certificate.Request) (*certificate.PEMCollection, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

	if req.PickupID == "" && req.CertID == "" && req.Thumbprint != "" {
		// search cert by Thumbprint and fill pickupID
		var certificateRequestId string
		searchResult, err := c.searchCertificatesByFingerprint(req.Thumbprint)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve certificate: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return nil, fmt.Errorf("no certificate found using fingerprint %s", req.Thumbprint)
		}

		var reqIds []string
		isOnlyOneCertificateRequestId := true
		for _, c := range searchResult.Certificates {
			reqIds = append(reqIds, c.CertificateRequestId)
			if certificateRequestId != "" && certificateRequestId != c.CertificateRequestId {
				isOnlyOneCertificateRequestId = false
			}
			if c.CertificateRequestId != "" {
				certificateRequestId = c.CertificateRequestId
			}
			if c.Id != "" {
				req.CertID = c.Id
			}
		}
		if !isOnlyOneCertificateRequestId {
			return nil, fmt.Errorf("more than one CertificateRequestId was found with the same Fingerprint: %s", reqIds)
		}

		req.PickupID = certificateRequestId
	}

	var certificateId string
	if req.CertID == "" && req.PickupID != "" {
		certId, err := c.getCertIDFromPickupID(req.PickupID, req.Timeout)
		if err != nil {
			return nil, err
		}
		certificateId = *certId
	} else {
		certificateId = req.CertID
	}

	// Download the private key and certificate in case the certificate is service generated
	if req.CsrOrigin == certificate.ServiceGeneratedCSR || req.FetchPrivateKey {
		var currentId string
		if req.CertID != "" {
			currentId = req.CertID
		} else if certificateId != "" {
			currentId = certificateId
		}

		dekInfo, err := getDekInfo(c, currentId)
		if err != nil {
			return nil, err
		}

		req.CertID = currentId
		return retrieveServiceGeneratedCertData(c, req, dekInfo)
	}

	url := c.getURL(urlResourceCertificateRetrievePem)
	url = fmt.Sprintf(url, certificateId)

	switch {
	case req.CertID != "":
		statusCode, status, body, err := c.waitForCertificate(url, req) //c.request("GET", url, nil)
		if err != nil {
			return nil, err
		}
		if statusCode != http.StatusOK {
			return nil, fmt.Errorf("failed to retrieve certificate. StatusCode: %d -- Status: %s -- Server Data: %s", statusCode, status, body)
		}
		return newPEMCollectionFromResponse(body, certificate.ChainOptionIgnore)
	case req.PickupID != "":
		url += "?chainOrder=%s&format=PEM"
		switch req.ChainOption {
		case certificate.ChainOptionRootFirst:
			url = fmt.Sprintf(url, condorChainOptionRootFirst)
		default:
			url = fmt.Sprintf(url, condorChainOptionRootLast)
		}
		statusCode, status, body, err := c.waitForCertificate(url, req) //c.request("GET", url, nil)
		if err != nil {
			return nil, err
		}
		if statusCode == http.StatusOK {
			certificates, err := newPEMCollectionFromResponse(body, req.ChainOption)
			if err != nil {
				return nil, err
			}
			err = req.CheckCertificate(certificates.Certificate)
			// Add certificate id to the request
			req.CertID = certificateId
			return certificates, err
		} else if statusCode == http.StatusConflict { // Http Status Code 409 means the certificate has not been signed by the ca yet.
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID}
		} else {
			return nil, fmt.Errorf("failed to retrieve certificate. StatusCode: %d -- Status: %s", statusCode, status)
		}
	}
	return nil, fmt.Errorf("couldn't retrieve certificate because both PickupID and CertId are empty")
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {
	if !c.isAuthenticated() {
		return "", fmt.Errorf("must be autheticated to request a certificate")
	}

	/* 1st step is to get CertificateRequestId which is required to lookup managedCertificateId and zoneId */
	var certificateRequestId string

	if renewReq.Thumbprint != "" {
		// by Thumbprint (aka Fingerprint)
		searchResult, err := c.searchCertificatesByFingerprint(renewReq.Thumbprint)
		if err != nil {
			return "", fmt.Errorf("failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return "", fmt.Errorf("no certificate found using fingerprint %s", renewReq.Thumbprint)
		}

		var reqIds []string
		isOnlyOneCertificateRequestId := true
		for _, c := range searchResult.Certificates {
			reqIds = append(reqIds, c.CertificateRequestId)
			if certificateRequestId != "" && certificateRequestId != c.CertificateRequestId {
				isOnlyOneCertificateRequestId = false
			}
			certificateRequestId = c.CertificateRequestId
		}
		if !isOnlyOneCertificateRequestId {
			return "", fmt.Errorf("error: more than one CertificateRequestId was found with the same Fingerprint: %s", reqIds)
		}
	} else if renewReq.CertificateDN != "" {
		// by CertificateDN (which is the same as CertificateRequestId for current implementation)
		certificateRequestId = renewReq.CertificateDN
	} else {
		return "", fmt.Errorf("failed to create renewal request: CertificateDN or Thumbprint required")
	}

	/* 2nd step is to get ManagedCertificateId & ZoneId by looking up certificate request record */
	previousRequest, err := c.getCertificateStatus(certificateRequestId)
	if err != nil {
		return "", fmt.Errorf("certificate renew failed: %s", err)
	}
	applicationId := previousRequest.ApplicationId
	templateId := previousRequest.TemplateId
	certificateId := previousRequest.CertificateIdsList[0]

	emptyField := ""
	if certificateId == "" {
		emptyField = "certificateId"
	} else if applicationId == "" {
		emptyField = "applicationId"
	} else if templateId == "" {
		emptyField = "templateId"
	}
	if emptyField != "" {
		return "", fmt.Errorf("failed to submit renewal request for certificate: %s is empty, certificate status is %s", emptyField, previousRequest.Status)
	}

	/* 3rd step is to get Certificate Object by id
	and check if latestCertificateRequestId there equals to certificateRequestId from 1st step */
	managedCertificate, err := c.getCertificate(certificateId)
	if err != nil {
		return "", fmt.Errorf("failed to renew certificate: %s", err)
	}
	if managedCertificate.CertificateRequestId != certificateRequestId {
		withThumbprint := ""
		if renewReq.Thumbprint != "" {
			withThumbprint = fmt.Sprintf("with thumbprint %s ", renewReq.Thumbprint)
		}
		return "", fmt.Errorf(
			"certificate under requestId %s %s is not the latest under CertificateId %s."+
				"The latest request is %s. This error may happen when revoked certificate is requested to be renewed",
			certificateRequestId, withThumbprint, certificateId, managedCertificate.CertificateRequestId)
	}

	/* 4th step is to send renewal request */
	url := c.getURL(urlResourceCertificateRequests)

	req := certificateRequest{
		ExistingCertificateId: certificateId,
		ApplicationId:         applicationId,
		TemplateId:            templateId,
	}

	if renewReq.CertificateRequest.Location != nil {
		workload := renewReq.CertificateRequest.Location.Workload
		if workload == "" {
			workload = defaultAppName
		}
		nodeName := renewReq.CertificateRequest.Location.Instance
		appName := workload

		req.CertificateUsageMetadata = []certificateUsageMetadata{
			{
				AppName:  appName,
				NodeName: nodeName,
			},
		}
	}

	if renewReq.CertificateRequest != nil && len(renewReq.CertificateRequest.GetCSR()) != 0 {
		req.CSR = string(renewReq.CertificateRequest.GetCSR())
		req.ReuseCSR = false
	} else {
		req.ReuseCSR = true
		return "", fmt.Errorf("reuseCSR option is not currently available for Renew Certificate operation. A new CSR must be provided in the request")
	}
	statusCode, status, body, err := c.request("POST", url, req)
	if err != nil {
		return
	}

	cr, err := parseCertificateRequestResult(statusCode, status, body)
	if err != nil {
		return "", fmt.Errorf("failed to renew certificate: %s", err)
	}
	return cr.CertificateRequests[0].ID, nil
}

// RetireCertificate attempts to retire the certificate
func (c *Connector) RetireCertificate(retireReq *certificate.RetireRequest) error {
	if !c.isAuthenticated() {
		return fmt.Errorf("must be autheticated to request a certificate")
	}

	url := c.getURL(urlResourceCertificatesRetirement)
	/* 1st step is to get CertificateRequestId which is required to retire certificate */
	var certificateRequestId string
	if retireReq.Thumbprint != "" {
		// by Thumbprint (aka Fingerprint)
		searchResult, err := c.searchCertificatesByFingerprint(retireReq.Thumbprint)
		if err != nil {
			return fmt.Errorf("failed to create retire request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return fmt.Errorf("no certificate found using fingerprint %s", retireReq.Thumbprint)
		}

		var reqIds []string
		isOnlyOneCertificateRequestId := true
		for _, c := range searchResult.Certificates {
			reqIds = append(reqIds, c.CertificateRequestId)
			if certificateRequestId != "" && certificateRequestId != c.CertificateRequestId {
				isOnlyOneCertificateRequestId = false
			}
			certificateRequestId = c.CertificateRequestId
		}
		if !isOnlyOneCertificateRequestId {
			return fmt.Errorf("error: more than one CertificateRequestId was found with the same Fingerprint: %s", reqIds)
		}
	} else if retireReq.CertificateDN != "" {
		// by CertificateDN (which is the same as CertificateRequestId for current implementation)
		certificateRequestId = retireReq.CertificateDN
	} else {
		return fmt.Errorf("failed to create retire request: CertificateDN or Thumbprint required")
	}

	/* 2nd step is to get ManagedCertificateId & ZoneId by looking up certificate request record */
	previousRequest, err := c.getCertificateStatus(certificateRequestId)
	if err != nil {
		if strings.Contains(err.Error(), "Unable to find certificateRequest") {
			return fmt.Errorf("invalid thumbprint or certificate ID. No certificates were retired")
		}
		return fmt.Errorf("certificate retirement failed: error on getting Certificate ID: %s", err)
	}
	certificateId := previousRequest.CertificateIdsList[0]

	/* Now we do retirement*/
	retRequest := certificateRetireRequest{
		CertificateIds: []string{certificateId},
	}

	statusCode, status, response, err := c.request("POST", url, retRequest)
	if err != nil {
		return err
	}

	err = checkCertificateRetireResults(statusCode, status, response)
	if err != nil {
		return err
	}

	return nil
}

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(_ *certificate.RevocationRequest) (err error) {
	return fmt.Errorf("not supported by endpoint")
}

func (c *Connector) ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

	pBlock, _ := pem.Decode([]byte(req.CertificateData))
	if pBlock == nil {
		return nil, fmt.Errorf("%w can`t parse certificate", verror.UserDataError)
	}
	zone := req.PolicyDN
	if zone == "" {
		appDetails, _, err := c.getAppDetailsByName(c.zone.getApplicationName())
		if err != nil {
			return nil, err
		}
		zone = appDetails.ApplicationId
	}
	ipAddr := endpoint.LocalIP
	origin := endpoint.SDKName
	for _, f := range req.CustomFields {
		if f.Type == certificate.CustomFieldOrigin {
			origin = f.Value
		}
	}
	base64.StdEncoding.EncodeToString(pBlock.Bytes)
	fingerprint := certThumbprint(pBlock.Bytes)
	request := importRequest{
		Certificates: []importRequestCertInfo{
			{
				Certificate:    base64.StdEncoding.EncodeToString(pBlock.Bytes),
				ApplicationIds: []string{zone},
				ApiClientInformation: apiClientInformation{
					Type:       origin,
					Identifier: ipAddr,
				},
			},
		},
	}

	url := c.getURL(urlResourceCertificates)
	statusCode, status, body, err := c.request("POST", url, request)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerTemporaryUnavailableError, err)
	}
	var r importResponse
	switch statusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted:
	case http.StatusBadRequest, http.StatusForbidden, http.StatusConflict:
		return nil, fmt.Errorf("%w: certificate can`t be imported. %d %s %s", verror.ServerBadDataResponce, statusCode, status, string(body))
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
		return nil, verror.ServerTemporaryUnavailableError
	default:
		return nil, verror.ServerError
	}
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, fmt.Errorf("%w: can`t unmarshal json response %s", verror.ServerError, err)
	} else if !(len(r.CertificateInformations) == 1) {
		return nil, fmt.Errorf("%w: certificate was not imported on unknown reason", verror.ServerBadDataResponce)
	}
	time.Sleep(time.Second)
	foundCert, err := c.searchCertificatesByFingerprint(fingerprint)
	if err != nil {
		return nil, err
	}
	if len(foundCert.Certificates) != 1 {
		return nil, fmt.Errorf("%w certificate has been imported but could not be found on platform after that", verror.ServerError)
	}
	cert := foundCert.Certificates[0]
	resp := &certificate.ImportResponse{CertificateDN: cert.SubjectCN[0], CertId: cert.Id}
	return resp, nil
}

func (c *Connector) ListCertificates(filter endpoint.Filter) ([]certificate.CertificateInfo, error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

	if c.zone.String() == "" {
		return nil, fmt.Errorf("empty zone")
	}
	const batchSize = 50
	limit := 100000000
	if filter.Limit != nil {
		limit = *filter.Limit
	}
	var buf [][]certificate.CertificateInfo
	for page := 0; limit > 0; limit, page = limit-batchSize, page+1 {
		var b []certificate.CertificateInfo
		var err error
		b, err = c.getCertsBatch(page, batchSize, filter.WithExpired)
		if limit < batchSize && len(b) > limit {
			b = b[:limit]
		}
		if err != nil {
			return nil, err
		}
		buf = append(buf, b)
		if len(b) < batchSize {
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

func (c *Connector) SearchCertificates(_ *certificate.SearchRequest) (*certificate.CertSearchResponse, error) {
	panic("operation is not supported yet")
}

func (c *Connector) SearchCertificate(zone string, cn string, sans *certificate.Sans, certMinTimeLeft time.Duration) (certificateInfo *certificate.CertificateInfo, err error) {
	if !c.isAuthenticated() {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

	// retrieve application name from zone
	appName := getAppNameFromZone(zone)
	// get application id from name
	app, _, err := c.getAppDetailsByName(appName)
	if err != nil {
		return nil, err
	}

	// format arguments for request
	req := formatSearchCertificateArguments(cn, sans, certMinTimeLeft)

	// perform request
	searchResult, err := c.searchCertificates(req)
	if err != nil {
		return nil, err
	}

	// fail if no certificate is returned from api
	if searchResult.Count == 0 {
		return nil, verror.NoCertificateFoundError
	}

	// map (convert) response to an array of CertificateInfo
	certificates := make([]*certificate.CertificateInfo, 0)
	n := 0
	for _, cert := range searchResult.Certificates {
		if util.ArrayContainsString(cert.ApplicationIds, app.ApplicationId) {
			match := cert.ToCertificateInfo()
			certificates = append(certificates, &match)
			n = n + 1
		}
	}

	// fail if no certificates found with matching zone
	if n == 0 {
		return nil, verror.NoCertificateWithMatchingZoneFoundError
	}

	// at this point all certificates belong to our zone, the next step is
	// finding the newest valid certificate matching the provided sans
	return certificate.FindNewestCertificateWithSans(certificates, sans)
}

func (c *Connector) getCertIDFromPickupID(pickupId string, timeout time.Duration) (*string, error) {
	if pickupId == "" {
		return nil, fmt.Errorf("pickupID cannot be empty in order to get certificate ID")
	}
	startTime := time.Now()
	//Wait for certificate to be issued by checking its PickupID
	//If certID is filled then certificate should be already issued.

	var certificateId string
	for {
		certStatus, err := c.getCertificateStatus(pickupId)
		if err != nil {
			return nil, fmt.Errorf("unable to retrieve: %s", err)
		}
		if certStatus.Status == "ISSUED" {
			certificateId = certStatus.CertificateIdsList[0]
			break // to fetch the cert itself
		} else if certStatus.Status == "FAILED" {
			return nil, fmt.Errorf("failed to retrieve certificate. Status: %v", certStatus)
		}
		if timeout == 0 {
			return nil, endpoint.ErrCertificatePending{CertificateID: pickupId, Status: certStatus.Status}
		} else {
			log.Println("Issuance of certificate is pending...")
		}
		if time.Now().After(startTime.Add(timeout)) {
			return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: pickupId}
		}
		time.Sleep(2 * time.Second)
	}
	if certificateId == "" {
		return nil, fmt.Errorf("something went wrong during polling cert status and we still got and empty CertificateID at the end")
	}

	return &certificateId, nil
}

func (c *Connector) IsCSRServiceGenerated(req *certificate.Request) (bool, error) {
	if !c.isAuthenticated() {
		return false, fmt.Errorf("must be autheticated to request a certificate")
	}

	if req.PickupID == "" && req.CertID == "" && req.Thumbprint != "" {
		// search cert by Thumbprint and fill pickupID
		var certificateRequestId string
		searchResult, err := c.searchCertificatesByFingerprint(req.Thumbprint)
		if err != nil {
			return false, fmt.Errorf("failed to retrieve certificate: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return false, fmt.Errorf("no certificate found using fingerprint %s", req.Thumbprint)
		}

		var reqIds []string
		for _, c := range searchResult.Certificates {
			reqIds = append(reqIds, c.CertificateRequestId)
			if certificateRequestId != "" && certificateRequestId != c.CertificateRequestId {
				return false, fmt.Errorf("more than one CertificateRequestId was found with the same Fingerprint: %s", reqIds)
			}
			if c.CertificateRequestId != "" {
				certificateRequestId = c.CertificateRequestId
			}
			if c.Id != "" {
				req.CertID = c.Id
			}
		}
		req.PickupID = certificateRequestId
	}

	var dekInfo *EdgeEncryptionKey
	var currentId string
	var err error
	if req.CertID != "" {
		dekInfo, err = getDekInfo(c, req.CertID)
	} else {
		var certificateId string
		certificateId, err = getCertificateId(c, req)
		if err == nil && certificateId != "" {
			dekInfo, err = getDekInfo(c, certificateId)
		}
	}

	if err == nil && dekInfo.Key != "" {
		req.CertID = currentId
		return true, err
	}
	return false, nil
}

func (c *Connector) RetrieveCertificateMetaData(_ string) (*certificate.CertificateMetaData, error) {
	panic("operation is not supported yet")
}

// SynchronousRequestCertificate It's not supported yet in VaaS
func (c *Connector) SynchronousRequestCertificate(_ *certificate.Request) (certificates *certificate.PEMCollection, err error) {
	panic("operation is not supported yet")
}

// SupportSynchronousRequestCertificate returns if the connector support synchronous calls to request a certificate.
func (c *Connector) SupportSynchronousRequestCertificate() bool {
	return false
}

func (c *Connector) RetrieveSystemVersion() (response string, err error) {
	panic("operation is not supported yet")
}

func getCertificateId(c *Connector, req *certificate.Request) (string, error) {
	startTime := time.Now()
	//Wait for certificate to be issued by checking its PickupID
	//If certID is filled then certificate should be already issued.
	for {
		if req.PickupID == "" {
			break
		}
		certStatus, err := c.getCertificateStatus(req.PickupID)
		if err != nil {
			return "", fmt.Errorf("unable to retrieve: %s", err)
		}
		if certStatus.Status == "ISSUED" {
			return certStatus.CertificateIdsList[0], nil
		} else if certStatus.Status == "FAILED" {
			return "", fmt.Errorf("failed to retrieve certificate. Status: %v", certStatus)
		}
		if req.Timeout == 0 {
			return "", endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: certStatus.Status}
		} else {
			log.Println("Issuance of certificate is pending...")
		}
		if time.Now().After(startTime.Add(req.Timeout)) {
			return "", endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
		}
		time.Sleep(2 * time.Second)
	}

	return "", endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
}

// normalizeURL allows overriding the default URL used to communicate with Venafi Cloud
func normalizeURL(url string) (normalizedURL string, err error) {
	if url == "" {
		url = apiURL
	}
	normalizedURL = util.NormalizeUrl(url)
	return normalizedURL, nil
}

func (c *Connector) GetAccessToken(auth *endpoint.Authentication) (*TLSPCAccessTokenResponse, error) {
	if auth == nil || auth.TokenURL == "" || auth.ExternalJWT == "" {
		return nil, fmt.Errorf("failed to authenticate: missing credentials")
	}

	url, err := getServiceAccountTokenURL(auth.TokenURL)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	body := netUrl.Values{}
	body.Set("grant_type", "client_credentials")
	body.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	body.Set("client_assertion", auth.ExternalJWT)

	r, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body.Encode()))
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.VcertError, err)
		return nil, err
	}
	r.Header.Set(headers.UserAgent, c.userAgent)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	httpClient := c.getHTTPClient()
	resp, err := httpClient.Do(r)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.ServerUnavailableError, err)
		return nil, err
	}

	statusCode := resp.StatusCode
	status := resp.Status

	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.ServerError, err)
		return nil, err
	}

	accessTokenResponse, err := parseAccessTokenResponse(http.StatusOK, statusCode, status, respBody)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(accessTokenResponse.TokenType, oauthTokenType) {
		return nil, fmt.Errorf(
			"%w: got an access token but token type is not %s. Expected: %s. Got: %s", verror.ServerError,
			oauthTokenType, oauthTokenType, accessTokenResponse.TokenType)
	}

	return accessTokenResponse, nil
}

func (c *Connector) isAuthenticated() bool {
	if c.accessToken != "" {
		return true
	}

	if c.apiKey != "" {
		return true
	}

	return false
}

func (c *Connector) getCloudRequest(req *certificate.Request) (*certificateRequest, error) {
	ipAddr := endpoint.LocalIP
	origin := endpoint.SDKName
	for _, f := range req.CustomFields {
		if f.Type == certificate.CustomFieldOrigin {
			origin = f.Value
		}
	}

	appDetails, _, err := c.getAppDetailsByName(c.zone.getApplicationName())
	if err != nil {
		return nil, err
	}
	templateId := appDetails.CitAliasToIdMap[c.zone.getTemplateAlias()]

	cloudReq := certificateRequest{
		ApplicationId: appDetails.ApplicationId,
		TemplateId:    templateId,
		ApiClientInformation: certificateRequestClientInfo{
			Type:       origin,
			Identifier: ipAddr,
		},
	}

	if req.CsrOrigin != certificate.ServiceGeneratedCSR {
		cloudReq.CSR = string(req.GetCSR())
	} else {

		cloudReq.IsVaaSGenerated = true
		csrAttr, err := getCsrAttributes(c, req)
		if err != nil {
			return nil, err
		}
		cloudReq.CsrAttributes = *(csrAttr)
		cloudReq.ApplicationServerTypeId = util.ApplicationServerTypeID

	}

	if req.Location != nil {
		workload := req.Location.Workload
		if workload == "" {
			workload = defaultAppName
		}
		nodeName := req.Location.Instance
		appName := workload

		cloudReq.CertificateUsageMetadata = []certificateUsageMetadata{
			{
				AppName:  appName,
				NodeName: nodeName,
			},
		}
	}

	validityDuration := req.ValidityDuration

	// DEPRECATED: ValidityHours is deprecated in favor of ValidityDuration, but we
	// still support it for backwards compatibility.
	if validityDuration == nil && req.ValidityHours > 0 { //nolint:staticcheck
		duration := time.Duration(req.ValidityHours) * time.Hour //nolint:staticcheck
		validityDuration = &duration
	}

	if validityDuration != nil {
		cloudReq.ValidityPeriod = "PT" + strings.ToUpper((*validityDuration).Truncate(time.Second).String())
	}

	return &cloudReq, nil
}

func (c *Connector) getCertificateStatus(requestID string) (certStatus *certificateStatus, err error) {
	url := c.getURL(urlResourceCertificateStatus)
	url = fmt.Sprintf(url, requestID)
	statusCode, _, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if statusCode == http.StatusOK {
		certStatus = &certificateStatus{}
		err = json.Unmarshal(body, certStatus)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate request status response: %s", err)
		}
		return
	}
	respErrors, err := parseResponseErrors(body)
	if err == nil {
		respError := fmt.Sprintf("Unexpected status code on Venafi Cloud certificate search. Status: %d\n", statusCode)
		for _, e := range respErrors {
			respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
		}
		return nil, errors.New(respError)
	}

	return nil, fmt.Errorf("unexpected status code on Venafi Cloud certificate search. Status: %d", statusCode)

}

func retrieveServiceGeneratedCertData(c *Connector, req *certificate.Request, dekInfo *EdgeEncryptionKey) (*certificate.PEMCollection, error) {

	pkDecoded, err := base64.StdEncoding.DecodeString(dekInfo.Key)

	if err != nil {
		return nil, err
	}

	publicKey, err := Load32KeyByte(pkDecoded)
	if err != nil {
		return nil, err
	}

	encrypted, err := box.SealAnonymous(nil, []byte(req.KeyPassword), publicKey, rand.Reader)

	if err != nil {
		return nil, err
	}

	//Request keystore
	ksRequest := KeyStoreRequest{
		ExportFormat:                  "PEM",
		EncryptedPrivateKeyPassphrase: base64.StdEncoding.EncodeToString(encrypted),
		EncryptedKeystorePassphrase:   "",
		CertificateLabel:              "",
	}

	url := c.getURL(urlResourceCertificateKS)
	url = fmt.Sprintf(url, req.CertID)

	statusCode, status, body, err := c.request("POST", url, ksRequest)

	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK && statusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to retrieve KeyStore on VaaS, status: %s", status)
	}

	rootFirst := false
	if req.ChainOption == certificate.ChainOptionRootFirst {
		rootFirst = true
	}

	return ConvertZipBytesToPem(body, rootFirst)

}

func getDekInfo(c *Connector, certId string) (*EdgeEncryptionKey, error) {
	//get certificate details for getting DekHash

	managedCert, err := c.getCertificate(certId)

	if err != nil {
		return nil, err
	}

	//get Dek info for getting DEK's key
	url := c.getURL(urlDekPublicKey)
	url = fmt.Sprintf(url, managedCert.DekHash)

	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}

	dekInfo, err := parseDEKInfo(statusCode, status, body)
	if err != nil {
		return nil, err
	}

	return dekInfo, nil

}

func ConvertZipBytesToPem(dataByte []byte, rootFirst bool) (*certificate.PEMCollection, error) {
	collection := certificate.PEMCollection{}
	var cert string
	var privateKey string
	var chainArr []string

	zipReader, err := zip.NewReader(bytes.NewReader(dataByte), int64(len(dataByte)))
	if err != nil {
		return nil, err
	}

	for _, zipFile := range zipReader.File {
		if strings.HasSuffix(zipFile.Name, ".key") {

			f, err := zipFile.Open()
			if err != nil {
				log.Println(err)
				continue
			}
			defer f.Close()
			fileBytes, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}

			privateKey = strings.TrimSpace(string(fileBytes)) + "\n"

		} else if strings.HasSuffix(zipFile.Name, "_root-first.pem") {

			f, err := zipFile.Open()

			if err != nil {
				return nil, err
			}

			defer f.Close()
			fileBytes, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}

			certs := strings.Split(strings.TrimSpace(string(fileBytes)), "\n\n")

			for i := 0; i < len(certs); i++ {
				if i < len(certs)-1 {
					if len(chainArr) == 0 {
						chainArr = append(chainArr, certs[i]+"\n")
					} else {
						if rootFirst {
							chainArr = append(chainArr, certs[i]+"\n")
						} else {
							chainArr = append([]string{certs[i] + "\n"}, chainArr...)
						}
					}
				} else {
					cert = certs[i] + "\n"
				}
			}
		}
	}

	collection.Certificate = cert
	collection.PrivateKey = privateKey
	collection.Chain = chainArr

	return &collection, nil
}

// Waits for the Certificate to be available. Fails when the timeout is exceeded
func (c *Connector) waitForCertificate(url string, request *certificate.Request) (statusCode int, status string, body []byte, err error) {
	startTime := time.Now()
	for {
		statusCode, status, body, err = c.request("GET", url, nil)
		if err != nil {
			return
		}
		if statusCode == http.StatusOK {
			return
		}
		if request.Timeout == 0 {
			err = endpoint.ErrCertificatePending{CertificateID: request.PickupID, Status: status}
			return
		}
		if time.Now().After(startTime.Add(request.Timeout)) {
			err = endpoint.ErrRetrieveCertificateTimeout{CertificateID: request.PickupID}
			return
		}
		time.Sleep(2 * time.Second)
	}
}

// WriteLog Custom Logging not currently supported by VaaS
func (c *Connector) WriteLog(_ *endpoint.LogRequest) (err error) {
	return fmt.Errorf("outbound logging not supported by endpoint")
}

func (c *Connector) searchCertificates(req *SearchRequest) (*CertificateSearchResponse, error) {

	var err error

	url := c.getURL(urlResourceCertificateSearch)
	statusCode, _, body, err := c.request("POST", url, req)
	if err != nil {
		return nil, err
	}
	searchResult, err := ParseCertificateSearchResponse(statusCode, body)
	if err != nil {
		return nil, err
	}
	return searchResult, nil
}

func (c *Connector) searchCertificatesByFingerprint(fp string) (*CertificateSearchResponse, error) {
	fp = strings.Replace(fp, ":", "", -1)
	fp = strings.Replace(fp, ".", "", -1)
	fp = strings.ToUpper(fp)
	req := &SearchRequest{
		Expression: &Expression{
			Operands: []Operand{
				{
					Field:    "fingerprint",
					Operator: MATCH,
					Value:    fp,
				},
			},
		},
	}
	return c.searchCertificates(req)
}

type managedCertificate struct {
	Id                   string `json:"id"`
	CompanyId            string `json:"companyId"`
	CertificateRequestId string `json:"certificateRequestId"`
	DekHash              string `json:"dekHash,omitempty"`
}

func (c *Connector) getCertificate(certificateId string) (*managedCertificate, error) {
	url := c.getURL(urlResourceCertificateByID)
	url = fmt.Sprintf(url, certificateId)

	// TODO: Remove following retry logic once VC-31590 is fixed
	// retry logic involves the loop to constantly, during 1 minute, to retry
	// to get certificate each 2 seconds when it is not found in certificate inventory
	timeout := time.Duration(60) * time.Second

	startTime := time.Now()
	for {
		statusCode, _, body, err := c.request("GET", url, nil)
		if err != nil {
			return nil, err
		}

		switch statusCode {
		case http.StatusOK:
			var res = &managedCertificate{}
			err = json.Unmarshal(body, res)
			if err != nil {
				return nil, fmt.Errorf("failed to parse search results: %s, body: %s", err, body)
			}
			return res, nil
		default:
			if body != nil {
				respErrors, err := parseResponseErrors(body)
				if err == nil {
					err = validateNotFoundTimeout(statusCode, startTime, timeout, certificateId, respErrors)
					if err != nil {
						return nil, err
					}
				}
				return nil, err
			}
			err = validateNotFoundTimeout(statusCode, startTime, timeout, certificateId, []responseError{})
			if err != nil {
				return nil, err
			}
		}
		time.Sleep(2 * time.Second)
	}
}

// validateNotFoundTimeout function that returns nil for not found error if waiting time for timeout is not
// completed. This is while status code is NotFound
func validateNotFoundTimeout(statusCode int, startTime time.Time, timeout time.Duration, certificateId string, respErrors []responseError) error {
	respError := fmt.Sprintf("unexpected status code on Venafi Cloud certificate search. Status: %d\n", statusCode)
	if statusCode == http.StatusNotFound {
		if time.Now().After(startTime.Add(timeout)) {
			return endpoint.ErrRetrieveCertificateTimeout{CertificateID: certificateId}
		}
	} else {
		if len(respErrors) > 0 {
			for _, e := range respErrors {
				respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
			}
			return errors.New(respError)
		}
		return errors.New(respError)
	}
	return nil
}

func (c *Connector) getCertsBatch(page, pageSize int, withExpired bool) ([]certificate.CertificateInfo, error) {

	appDetails, _, err := c.getAppDetailsByName(c.zone.getApplicationName())
	if err != nil {
		return nil, err
	}

	req := &SearchRequest{
		Expression: &Expression{
			Operands: []Operand{
				{
					Field:    "appstackIds",
					Operator: MATCH,
					Value:    appDetails.ApplicationId,
				},
			},
			Operator: AND,
		},
		Paging: &Paging{PageSize: pageSize, PageNumber: page},
	}
	if !withExpired {
		req.Expression.Operands = append(req.Expression.Operands, Operand{
			Field:    "validityEnd",
			Operator: GTE,
			Value:    time.Now().Format(time.RFC3339),
		})
	}
	r, err := c.searchCertificates(req)
	if err != nil {
		return nil, err
	}
	infos := make([]certificate.CertificateInfo, len(r.Certificates))
	for i, cert := range r.Certificates {
		infos[i] = cert.ToCertificateInfo()
	}
	return infos, nil
}

func (c *Connector) getAppDetailsByName(appName string) (*ApplicationDetails, int, error) {
	url := c.getURL(urlAppDetailsByName)
	encodedAppName := netUrl.PathEscape(appName)
	url = fmt.Sprintf(url, encodedAppName)
	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, statusCode, err
	}
	details, err := parseApplicationDetailsResult(statusCode, status, body)
	if err != nil {
		return nil, statusCode, err
	}
	return details, statusCode, nil
}

func (c *Connector) getTemplateByID() (*certificateTemplate, error) {
	url := c.getURL(urlResourceTemplate)
	appNameEncoded := netUrl.PathEscape(c.zone.getApplicationName())
	citAliasEncoded := netUrl.PathEscape(c.zone.getTemplateAlias())
	url = fmt.Sprintf(url, appNameEncoded, citAliasEncoded)
	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	t, err := parseCertificateTemplateResult(statusCode, status, body)
	return t, err
}

func getCit(c *Connector, citName string) (*certificateTemplate, error) {
	url := c.getURL(urlIssuingTemplate)
	_, _, body, err := c.request("GET", url, nil)

	if err != nil {
		return nil, err
	}

	var cits CertificateTemplates

	err = json.Unmarshal(body, &cits)
	if err != nil {
		return nil, err
	}

	if len(cits.CertificateTemplates) > 0 {
		citArr := cits.CertificateTemplates

		for _, cit := range citArr {
			if citName == cit.Name {
				return &cit, nil
			}
		}

	}

	//no error but cit was not found.
	return nil, nil
}

func (c *Connector) CreateAPIUserAccount(userName string, password string) (int, *userDetails, error) {

	indexOfAt := strings.Index(userName, "@")

	if indexOfAt == -1 {
		indexOfAt = len(userName)
	}

	userAccountReq := userAccount{
		UserAccountType: "API",
		Username:        userName,
		Password:        password,
		Firstname:       userName[0:indexOfAt], //Given the issue reported in https://jira.eng.venafi.com/browse/VC-16461 its
		// required the workaround to set something on firstName or lastName field. For now, we are setting the email's prefix
	}

	return c.CreateUserAccount(&userAccountReq)
}

func (c *Connector) CreateUserAccount(userAccount *userAccount) (int, *userDetails, error) {

	url := c.getURL(urlResourceUserAccounts)
	statusCode, status, body, err := c.request("POST", url, userAccount, true)
	if err != nil {
		return statusCode, nil, err
	}
	ud, err := parseUserDetailsResultFromPOST(statusCode, status, body)
	if err != nil {
		return statusCode, nil, err
	}
	return statusCode, ud, nil
}

func (c *Connector) getUserDetails() (*userDetails, error) {
	url := c.getURL(urlResourceUserAccounts)
	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	ud, err := parseUserDetailsResult(http.StatusOK, statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return ud, nil
}

func (c *Connector) retrieveUser(id string) (*user, error) {

	url := c.getURL(urlUserById)
	url = fmt.Sprintf(url, id)

	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	user, err := parseUserByIdResult(http.StatusOK, statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (c *Connector) retrieveUsers(userName string) (*users, error) {

	url := c.getURL(urlUsersByName)
	url = fmt.Sprintf(url, userName)

	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	users, err := parseUsersByNameResult(http.StatusOK, statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return users, nil
}

func (c *Connector) retrieveTeams() (*teams, error) {

	url := c.getURL(urlTeams)

	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	teams, err := parseTeamsResult(http.StatusOK, statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return teams, nil
}

func (c *Connector) getCertificates(certificateId string) (*VenafiCertificate, error) {
	url := c.getURL(urlCertificateDetails)
	url = fmt.Sprintf(url, certificateId)

	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	cert, err := parseCertByIdResult(http.StatusOK, statusCode, status, body)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func getAccounts(caName string, c *Connector) (*policy.Accounts, *policy.CertificateAuthorityInfo, error) {
	info, err := policy.GetCertAuthorityInfo(caName)
	if err != nil {
		return nil, nil, err
	}

	caType := netUrl.PathEscape(info.CAType)
	url := c.getURL(urlCAAccounts)
	url = fmt.Sprintf(url, caType)
	_, _, body, err := c.request("GET", url, nil)

	if err != nil {
		return nil, nil, err
	}

	var accounts policy.Accounts

	err = json.Unmarshal(body, &accounts)

	if err != nil {
		return nil, nil, err
	}

	return &accounts, &info, nil
}

func getCertificateAuthorityDetails(caName string, c *Connector) (*policy.CADetails, error) {

	accounts, info, err := getAccounts(caName, c)
	if err != nil {
		return nil, err
	}

	var details policy.CADetails

	for _, account := range accounts.Accounts {
		if account.Account.Key == info.CAAccountKey {
			for _, productOption := range account.ProductOption {
				if productOption.ProductName == info.VendorProductName {
					productOptionOrganizationId := productOption.ProductDetails.ProductTemplate.OrganizationId
					details.CertificateAuthorityOrganizationId = &productOptionOrganizationId
					productionOptionId := productOption.Id
					details.CertificateAuthorityProductOptionId = &productionOptionId
					return &details, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("specified CA doesn't exist")
}

func getCertificateAuthorityInfoFromCloud(caName, caAccountId, caProductOptionId string, c *Connector) (*policy.CertificateAuthorityInfo, error) {

	caName = netUrl.PathEscape(caName)
	url := c.getURL(urlCAAccountDetails)
	url = fmt.Sprintf(url, caName, caAccountId)
	_, _, body, err := c.request("GET", url, nil)

	if err != nil {
		return nil, err
	}

	var accountDetails policy.AccountDetails

	err = json.Unmarshal(body, &accountDetails)

	if err != nil {
		return nil, err
	}

	var info policy.CertificateAuthorityInfo

	if accountDetails.Account.CertificateAuthority == "" {
		return nil, fmt.Errorf("CertificateAuthority is empty")
	}
	info.CAType = accountDetails.Account.CertificateAuthority

	if accountDetails.Account.Key == "" {
		return nil, fmt.Errorf("key is empty")
	}

	info.CAAccountKey = accountDetails.Account.Key

	for _, productOption := range accountDetails.ProductOption {
		if productOption.Id == caProductOptionId {
			info.VendorProductName = productOption.ProductName
		}
	}

	if info.VendorProductName == "" {
		return nil, fmt.Errorf("ProductName is empty")
	}

	return &info, nil
}
