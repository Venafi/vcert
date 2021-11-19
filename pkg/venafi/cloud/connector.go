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
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	netUrl "net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/Venafi/vcert/v4/pkg/verror"

	"golang.org/x/crypto/nacl/box"
)

type urlResource string

const (
	apiURL                                        = "api.venafi.cloud/"
	apiVersion                                    = "v1/"
	basePath                                      = "outagedetection/" + apiVersion
	urlResourceUserAccounts           urlResource = apiVersion + "useraccounts"
	urlResourceCertificateRequests    urlResource = basePath + "certificaterequests"
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
	urlCAAccountDetails               urlResource = urlCAAccounts + "/%s"
	urlResourceCertificateKS                      = urlResourceCertificates + "/%s/keystore"
	urlDekPublicKey                   urlResource = apiVersion + "edgeencryptionkeys/%s"

	defaultAppName = "Default"
)

type condorChainOption string

const (
	condorChainOptionRootFirst condorChainOption = "ROOT_FIRST"
	condorChainOptionRootLast  condorChainOption = "EE_FIRST"
)

// Connector contains the base data needed to communicate with the Venafi Cloud servers
type Connector struct {
	baseURL string
	apiKey  string
	verbose bool
	user    *userDetails
	trust   *x509.CertPool
	zone    cloudZone
	client  *http.Client
}

func (c *Connector) IsCSRServiceGenerated(req *certificate.Request) (bool, error) {
	if c.user == nil || c.user.Company == nil {
		return false, fmt.Errorf("must be autheticated to retieve certificate")
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

func getCertificateId(c *Connector, req *certificate.Request) (string, error) {
	startTime := time.Now()
	//Wait for certificate to be issued by checking it's PickupID
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

func (c *Connector) RetrieveSshConfig(ca *certificate.SshCaTemplateRequest) (*certificate.SshConfig, error) {
	panic("operation is not supported yet")
}

func (c *Connector) RetrieveSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) RequestSSHCertificate(req *certificate.SshCertRequest) (response *certificate.SshCertificateObject, err error) {
	panic("operation is not supported yet")
}

func (c *Connector) GetPolicyWithRegex(name string) (*policy.PolicySpecification, error) {

	cit, err := retrievePolicySpecification(c, name)

	if err != nil {
		return nil, err
	}

	info, err := getCertificateAuthorityInfoFromCloud(cit.CertificateAuthority, cit.CertificateAuthorityAccountId, cit.CertificateAuthorityProductOptionId, c)

	if err != nil {
		return nil, err
	}

	log.Println("Building policy")
	ps := buildPolicySpecification(cit, info, false)

	return ps, nil
}

func retrievePolicySpecification(c *Connector, name string) (*certificateTemplate, error) {
	appName := policy.GetApplicationName(name)
	if appName != "" {
		c.zone.appName = appName
	} else {
		return nil, fmt.Errorf("application name is not valid, please provide a valid zone name in the format: appName\\CitName")
	}
	citName := policy.GetCitName(name)
	if citName != "" {
		c.zone.templateAlias = citName
	} else {
		return nil, fmt.Errorf("cit name is not valid, please provide a valid zone name in the format: appName\\CitName")
	}

	log.Println("Getting CIT")
	cit, err := c.getTemplateByID()

	if err != nil {
		return nil, err
	}

	return cit, nil

}

func (c *Connector) GetPolicy(name string) (*policy.PolicySpecification, error) {

	cit, err := retrievePolicySpecification(c, name)
	if err != nil {
		return nil, err
	}

	info, err := getCertificateAuthorityInfoFromCloud(cit.CertificateAuthority, cit.CertificateAuthorityAccountId, cit.CertificateAuthorityProductOptionId, c)

	if err != nil {
		return nil, err
	}

	log.Println("Building policy")
	ps := buildPolicySpecification(cit, info, true)

	return ps, nil
}

func PolicyExist(policyName string, c *Connector) (bool, error) {

	c.zone.appName = policy.GetApplicationName(policyName)
	citName := policy.GetCitName(policyName)
	if citName != "" {
		c.zone.templateAlias = citName
	} else {
		return false, fmt.Errorf("cit name is not valid, please provide a valid zone name in the format: appName\\CitName")
	}

	_, err := c.getTemplateByID()
	return err == nil, nil
}

func (c *Connector) SetPolicy(name string, ps *policy.PolicySpecification) (string, error) {

	err := policy.ValidateCloudPolicySpecification(ps)
	if err != nil {
		return "", err
	}

	log.Printf("policy specification is valid")

	var status string

	//validate if zone name is set and if zone already exist on Venafi cloud if not create it.
	citName := policy.GetCitName(name)

	if citName == "" {
		return "", fmt.Errorf("cit name is empty, please provide zone in the format: app_name\\cit_name")
	}

	//get certificate authority product option io
	var caDetails *policy.CADetails

	if ps.Policy != nil && ps.Policy.CertificateAuthority != nil && *(ps.Policy.CertificateAuthority) != "" {
		caDetails, err = getCertificateAuthorityDetails(*(ps.Policy.CertificateAuthority), c)

		if err != nil {
			return "", err
		}

	} else {
		if ps.Policy != nil {

			defaultCA := policy.DefaultCA
			ps.Policy.CertificateAuthority = &defaultCA

			caDetails, err = getCertificateAuthorityDetails(*(ps.Policy.CertificateAuthority), c)

			if err != nil {
				return "", err
			}

		} else {
			//policy is not specified so we get the default CA
			caDetails, err = getCertificateAuthorityDetails(policy.DefaultCA, c)

			if err != nil {
				return "", err
			}

		}
	}

	//at this moment we know that ps.Policy.CertificateAuthority is valid.

	req, err := policy.BuildCloudCitRequest(ps, caDetails)
	if err != nil {
		return "", err
	}
	req.Name = citName

	url := c.getURL(urlIssuingTemplate)

	cit, err := getCit(c, citName)

	if err != nil {
		return "", err
	}

	if cit != nil {
		log.Printf("updating issuing template: %s", citName)
		//update cit using the new values
		url = fmt.Sprint(url, "/", cit.ID)
		statusCode, status, body, err := c.request("PUT", url, req)

		if err != nil {
			return "", err
		}

		cit, err = parseCitResult(http.StatusOK, statusCode, status, body)

		if err != nil {
			return status, err
		}

	} else {
		log.Printf("creating issuing template: %s", citName)
		//var body []byte
		statusCode, status, body, err := c.request("POST", url, req)

		if err != nil {
			return "", err
		}

		cit, err = parseCitResult(http.StatusCreated, statusCode, status, body)

		if err != nil {
			return status, err
		}

	}

	//validate if appName is set and if app already exist on Venafi cloud if not create it
	//and as final steps link the app with the cit.
	appName := policy.GetApplicationName(name)

	if appName == "" {
		return "", fmt.Errorf("application name is empty, please provide zone in the format: app_name\\cit_name")
	}

	userDetails, err := getUserDetails(c)
	if err != nil {
		return "", err
	}

	appDetails, statusCode, err := c.getAppDetailsByName(appName)

	if err != nil && statusCode == 404 { //means application was not found.
		log.Printf("creating application: %s", appName)
		ownerId := policy.OwnerIdType{
			OwnerId:   userDetails.User.ID,
			OwnerType: "USER",
		}

		appIssuingTemplate := make(map[string]string)
		appIssuingTemplate[cit.Name] = cit.ID

		//create application
		//fmt.Println(details.ApplicationId)
		appReq := policy.ApplicationCreateRequest{
			OwnerIdsAndTypes:                     []policy.OwnerIdType{ownerId},
			Name:                                 appName,
			CertificateIssuingTemplateAliasIdMap: appIssuingTemplate,
		}

		url := c.getURL(urlAppRoot)

		_, status, _, err = c.request("POST", url, appReq)
		if err != nil {
			return "", err
		}

	} else {
		//update the application and assign the cit tho the application
		exist, err := PolicyExist(name, c)

		if err != nil {
			return "", err
		}

		if !exist { // relation between app-cit doesn't exist so create it.
			log.Printf("updating application: %s", appName)

			appReq := createAppUpdateRequest(appDetails, cit)

			url := c.getURL(urlAppRoot)

			url = fmt.Sprint(url, "/", appDetails.ApplicationId)

			_, status, _, err = c.request("PUT", url, appReq)
			if err != nil {
				return "", err
			}

		}
	}

	log.Printf("policy successfully applied to %s", name)

	return status, nil
}

// NewConnector creates a new Venafi Cloud Connector object used to communicate with Venafi Cloud
func NewConnector(url string, zone string, verbose bool, trust *x509.CertPool) (*Connector, error) {
	cZone := cloudZone{zone: zone}
	c := Connector{verbose: verbose, trust: trust, zone: cZone}

	var err error
	c.baseURL, err = normalizeURL(url)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

//normalizeURL allows overriding the default URL used to communicate with Venafi Cloud
func normalizeURL(url string) (normalizedURL string, err error) {
	if url == "" {
		url = apiURL
		//return "", fmt.Errorf("base URL cannot be empty")
	}
	modified := strings.ToLower(url)
	reg := regexp.MustCompile("^http(|s)://")
	if reg.FindStringIndex(modified) == nil {
		modified = "https://" + modified
	} else {
		modified = reg.ReplaceAllString(modified, "https://")
	}
	if !strings.HasSuffix(modified, "/") {
		modified = modified + "/"
	}
	normalizedURL = modified
	return normalizedURL, nil
}

func (c *Connector) SetZone(z string) {
	cZone := cloudZone{zone: z}
	c.zone = cZone
}

func (c *Connector) GetType() endpoint.ConnectorType {
	return endpoint.ConnectorTypeCloud
}

// Ping attempts to connect to the Venafi Cloud API and returns an errror if it cannot
func (c *Connector) Ping() (err error) {

	return nil
}

// Authenticate authenticates the user with Venafi Cloud using the provided API Key
func (c *Connector) Authenticate(auth *endpoint.Authentication) (err error) {
	if auth == nil {
		return fmt.Errorf("failed to authenticate: missing credentials")
	}
	c.apiKey = auth.APIKey
	url := c.getURL(urlResourceUserAccounts)
	statusCode, status, body, err := c.request("GET", url, nil, true)
	if err != nil {
		return err
	}
	ud, err := parseUserDetailsResult(http.StatusOK, statusCode, status, body)
	if err != nil {
		return
	}
	c.user = ud
	return
}

func (c *Connector) ReadPolicyConfiguration() (policy *endpoint.Policy, err error) {
	config, err := c.ReadZoneConfiguration()
	if err != nil {
		return nil, err
	}
	policy = &config.Policy
	return
}

// ReadZoneConfiguration reads the Zone information needed for generating and requesting a certificate from Venafi Cloud
func (c *Connector) ReadZoneConfiguration() (config *endpoint.ZoneConfiguration, err error) {
	template, err := c.getTemplateByID()
	if err != nil {
		return
	}
	config = getZoneConfiguration(template)
	return config, nil
}

func getCloudRequest(c *Connector, req *certificate.Request) (*certificateRequest, error) {

	if c.user == nil || c.user.Company == nil {
		return nil, fmt.Errorf("must be autheticated to request a certificate")
	}

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

	if req.ValidityHours > 0 {
		hoursStr := strconv.Itoa(req.ValidityHours)
		validityHoursStr := "PT" + hoursStr + "H"
		cloudReq.ValidityPeriod = validityHoursStr
	}

	return &cloudReq, nil

}

// RequestCertificate submits the CSR to the Venafi Cloud API for processing
func (c *Connector) RequestCertificate(req *certificate.Request) (requestID string, err error) {

	url := c.getURL(urlResourceCertificateRequests)
	cloudReq, err := getCloudRequest(c, req)
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
		return nil, fmt.Errorf(respError)
	}

	return nil, fmt.Errorf("unexpected status code on Venafi Cloud certificate search. Status: %d", statusCode)

}

// RetrieveCertificate retrieves the certificate for the specified ID
func (c *Connector) RetrieveCertificate(req *certificate.Request) (certificates *certificate.PEMCollection, err error) {

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

	startTime := time.Now()
	//Wait for certificate to be issued by checking it's PickupID
	//If certID is filled then certificate should be already issued.
	var certificateId string
	if req.CertID == "" {
		for {
			if req.PickupID == "" {
				break
			}
			certStatus, err := c.getCertificateStatus(req.PickupID)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve: %s", err)
			}
			if certStatus.Status == "ISSUED" {
				certificateId = certStatus.CertificateIdsList[0]
				break // to fetch the cert itself
			} else if certStatus.Status == "FAILED" {
				return nil, fmt.Errorf("failed to retrieve certificate. Status: %v", certStatus)
			}
			// status.Status == "REQUESTED" || status.Status == "PENDING"
			if req.Timeout == 0 {
				return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID, Status: certStatus.Status}
			} else {
				log.Println("Issuance of certificate is pending...")
			}
			if time.Now().After(startTime.Add(req.Timeout)) {
				return nil, endpoint.ErrRetrieveCertificateTimeout{CertificateID: req.PickupID}
			}
			// fmt.Printf("pending... %s\n", status.Status)
			time.Sleep(2 * time.Second)
		}
	} else {
		certificateId = req.CertID
	}

	if c.user == nil || c.user.Company == nil {
		return nil, fmt.Errorf("must be autheticated to retieve certificate")
	}

	url := c.getURL(urlResourceCertificateRetrievePem)
	url = fmt.Sprintf(url, certificateId)

	var dekInfo *EdgeEncryptionKey
	var currentId string
	if req.CertID != "" {
		dekInfo, err = getDekInfo(c, req.CertID)
		currentId = req.CertID
	} else if certificateId != "" {
		dekInfo, err = getDekInfo(c, certificateId)
		currentId = certificateId
	}
	if err == nil && dekInfo.Key != "" {
		req.CertID = currentId
		return retrieveServiceGeneratedCertData(c, req, dekInfo)
	}

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
			certificates, err = newPEMCollectionFromResponse(body, req.ChainOption)
			if err != nil {
				return nil, err
			}
			err = req.CheckCertificate(certificates.Certificate)
			return certificates, err
		} else if statusCode == http.StatusConflict { // Http Status Code 409 means the certificate has not been signed by the ca yet.
			return nil, endpoint.ErrCertificatePending{CertificateID: req.PickupID}
		} else {
			return nil, fmt.Errorf("failed to retrieve certificate. StatusCode: %d -- Status: %s", statusCode, status)
		}
	}
	return nil, fmt.Errorf("couldn't retrieve certificate because both PickupID and CertId are empty")
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

func getDekInfo(c *Connector, cerId string) (*EdgeEncryptionKey, error) {
	//get certificate details for getting DekHash
	url := c.getURL(urlResourceCertificateByID)
	url = fmt.Sprintf(url, cerId)

	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}

	managedCert, err := parseCertificateInfo(statusCode, status, body)

	if err != nil {
		return nil, err
	}

	//get Dek info for getting DEK's key
	url = c.getURL(urlDekPublicKey)
	url = fmt.Sprintf(url, managedCert.DekHash)

	statusCode, status, body, err = c.request("GET", url, nil)
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
	var certificate string
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
			fileBytes, err := ioutil.ReadAll(f)
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
			fileBytes, err := ioutil.ReadAll(f)
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
					certificate = certs[i] + "\n"
				}
			}
		}
	}

	collection.Certificate = certificate
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

// RevokeCertificate attempts to revoke the certificate
func (c *Connector) RevokeCertificate(revReq *certificate.RevocationRequest) (err error) {
	return fmt.Errorf("not supported by endpoint")
}

// RenewCertificate attempts to renew the certificate
func (c *Connector) RenewCertificate(renewReq *certificate.RenewalRequest) (requestID string, err error) {

	/* 1st step is to get CertificateRequestId which is required to lookup managedCertificateId and zoneId */
	var certificateRequestId string

	if renewReq.Thumbprint != "" {
		// by Thumbprint (aka Fingerprint)
		searchResult, err := c.searchCertificatesByFingerprint(renewReq.Thumbprint)
		if err != nil {
			return "", fmt.Errorf("failed to create renewal request: %s", err)
		}
		if len(searchResult.Certificates) == 0 {
			return "", fmt.Errorf("no certifiate found using fingerprint %s", renewReq.Thumbprint)
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
	if c.user == nil || c.user.Company == nil {
		return "", fmt.Errorf("must be autheticated to request a certificate")
	}

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
					"fingerprint",
					MATCH,
					fp,
				},
			},
		},
	}
	return c.searchCertificates(req)
}

/*
  "id": "32a656d1-69b1-11e8-93d8-71014a32ec53",
  "companyId": "b5ed6d60-22c4-11e7-ac27-035f0608fd2c",
  "latestCertificateRequestId": "0e546560-69b1-11e8-9102-a1f1c55d36fb",
  "ownerUserId": "593cdba0-2124-11e8-8219-0932652c1da0",
  "certificateIds": [
    "32a656d0-69b1-11e8-93d8-71014a32ec53"
  ],
  "certificateName": "cn=svc6.venafi.example.com",

*/
type managedCertificate struct {
	Id                   string `json:"id"`
	CompanyId            string `json:"companyId"`
	CertificateRequestId string `json:"certificateRequestId"`
	DekHash              string `json:"dekHash,omitempty"`
}

func (c *Connector) getCertificate(certificateId string) (*managedCertificate, error) {
	var err error
	url := c.getURL(urlResourceCertificateByID)
	url = fmt.Sprintf(url, certificateId)
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
				respError := fmt.Sprintf("unexpected status code on Venafi Cloud certificate search. Status: %d\n", statusCode)
				for _, e := range respErrors {
					respError += fmt.Sprintf("Error Code: %d Error: %s\n", e.Code, e.Message)
				}
				return nil, fmt.Errorf(respError)
			}
		}
		return nil, fmt.Errorf("unexpected status code on Venafi Cloud certificate search. Status: %d", statusCode)
	}
}

func (c *Connector) ImportCertificate(req *certificate.ImportRequest) (*certificate.ImportResponse, error) {
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

func (c *Connector) SetHTTPClient(client *http.Client) {
	c.client = client
}

func (c *Connector) ListCertificates(filter endpoint.Filter) ([]certificate.CertificateInfo, error) {
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

func (c *Connector) getCertsBatch(page, pageSize int, withExpired bool) ([]certificate.CertificateInfo, error) {

	appDetails, _, err := c.getAppDetailsByName(c.zone.getApplicationName())
	if err != nil {
		return nil, err
	}

	req := &SearchRequest{
		Expression: &Expression{
			Operands: []Operand{
				{"appstackIds", MATCH, appDetails.ApplicationId},
			},
			Operator: AND,
		},
		Paging: &Paging{PageSize: pageSize, PageNumber: page},
	}
	if !withExpired {
		req.Expression.Operands = append(req.Expression.Operands, Operand{
			"validityEnd",
			GTE,
			time.Now().Format(time.RFC3339),
		})
	}
	r, err := c.searchCertificates(req)
	if err != nil {
		return nil, err
	}
	infos := make([]certificate.CertificateInfo, len(r.Certificates))
	for i, c := range r.Certificates {
		infos[i] = c.ToCertificateInfo()
	}
	return infos, nil
}

func (c *Connector) getAppDetailsByName(appName string) (*ApplicationDetails, int, error) {
	url := c.getURL(urlAppDetailsByName)
	if c.user == nil {
		return nil, -1, fmt.Errorf("must be autheticated to read the zone configuration")
	}
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

func getUserDetails(c *Connector) (*userDetails, error) {

	url := c.getURL(urlResourceUserAccounts)
	statusCode, status, body, err := c.request("GET", url, nil)
	if err != nil {
		return nil, err
	}
	ud, err := parseUserDetailsResult(http.StatusOK, statusCode, status, body)
	if err != nil {
		return nil, err
	}
	c.user = ud
	return ud, nil
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
					details.CertificateAuthorityOrganizationId = &productOption.ProductDetails.ProductTemplate.OrganizationId
					details.CertificateAuthorityProductOptionId = &productOption.Id
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
		return nil, fmt.Errorf("Key is empty")
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
