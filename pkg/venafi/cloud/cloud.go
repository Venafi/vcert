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
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/verror"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
)

type apiKey struct {
	Username                string    `json:"username,omitempty"`
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

type certificateRequestResponse struct {
	CertificateRequests []certificateRequestResponseData `json:"certificateRequests,omitempty"`
}

type certificateRequestResponseData struct {
	ID                     string    `json:"id,omitempty"`
	ZoneID                 string    `json:"zoneId,omitempty"`
	Status                 string    `json:"status,omitempty"`
	SubjectDN              string    `json:"subjectDN,omitempty"`
	GeneratedKey           bool      `json:"generatedKey,omitempty"`
	DefaultKeyPassword     bool      `json:"defaultKeyPassword,omitempty"`
	CertificateInstanceIDs []string  `json:"certificateInstanceIds,omitempty"`
	CreationDateString     string    `json:"creationDate,omitempty"`
	CreationDate           time.Time `json:"-"`
	PEM                    string    `json:"pem,omitempty"`
	DER                    string    `json:"der,omitempty"`
}

type certificateRequestClientInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type certificateRequest struct {
	CSR                          string                       `json:"certificateSigningRequest,omitempty"`
	ZoneID                       string                       `json:"zoneId,omitempty"`
	ExistingManagedCertificateId string                       `json:"existingManagedCertificateId,omitempty"`
	ReuseCSR                     bool                         `json:"reuseCSR,omitempty"`
	ApiClientInformation         certificateRequestClientInfo `json:"apiClientInformation,omitempty"`
	ValidityPeriod               string                       `json:"validityPeriod,omitempty"`
}

type certificateStatus struct {
	Id                        string                            `json:"Id,omitempty"`
	ManagedCertificateId      string                            `json:"managedCertificateId,omitempty"`
	ZoneId                    string                            `json:"zoneId,omitempty"`
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

type importRequestClientInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type importRequestInstanceInfo struct {
	AppName            string `json:"appName,omitempty"`
	NodeName           string `json:"nodeName,omitempty"`
	AutomationMetadata string `json:"automationMetadata,omitempty"`
}

type importRequest struct {
	Certificate              string                      `json:"certificate"`
	IssuerCertificates       []string                    `json:"issuerCertificates,omitempty"`
	ZoneId                   string                      `json:"zoneId"`
	CertificateName          string                      `json:"certificateName"`
	ApiClientInformation     importRequestClientInfo     `json:"apiClientInformation,omitempty"`
	CertificateUsageMetadata []importRequestInstanceInfo `json:"certificateUsageMetadata,omitempty"`
}

type importResponseClientInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type importResponseCertInfo struct {
	Id                      string                   `json:"id"`
	ManagedCertificateId    string                   `json:"managedCertificateId"`
	CompanyId               string                   `json:"companyId"`
	Fingerprint             string                   `json:"fingerprint"`
	CertificateSource       string                   `json:"certificateSource"`
	OwnerUserId             string                   `json:"ownerUserId"`
	IssuanceZoneId          string                   `json:"issuanceZoneId"`
	ValidityStartDateString string                   `json:"validityStartDate"`
	ValidityStartDate       time.Time                `json:"-"`
	ValidityEndDateString   string                   `json:"validityEndDate"`
	ValidityEndDate         time.Time                `json:"-"`
	ApiClientInformation    importResponseClientInfo `json:"apiClientInformation,omitempty"`
}

type importResponse struct {
	CertificateInformations []importResponseCertInfo `json:"certificateInformations"`
}

//GenerateRequest generates a CertificateRequest based on the zone configuration, and returns the request along with the private key.
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
			DualStack: true,
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
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		tlsConfig.RootCAs = c.trust
	}
	netTransport.TLSClientConfig = tlsConfig
	c.client = &http.Client{
		Timeout:   time.Second * 30,
		Transport: netTransport,
	}
	return c.client
}

func (c *Connector) request(method string, url string, data interface{}, authNotRequired ...bool) (statusCode int, statusText string, body []byte, err error) {
	if c.user == nil || c.user.Company == nil {
		if !(len(authNotRequired) == 1 && authNotRequired[0]) {
			err = fmt.Errorf("%w: must be autheticated to retieve certificate", verror.VcertError)
			return
		}
	}

	var payload io.Reader
	var b []byte
	if method == "POST" {
		b, _ = json.Marshal(data)
		payload = bytes.NewReader(b)
	}

	r, err := http.NewRequest(method, url, payload)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.VcertError, err)
		return
	}
	if c.apiKey != "" {
		r.Header.Add("tppl-api-key", c.apiKey)
	}
	if method == "POST" {
		r.Header.Add("Accept", "application/json")
		r.Header.Add("content-type", "application/json")
	} else {
		r.Header.Add("Accept", "*/*")
	}
	r.Header.Add("cache-control", "no-cache")

	var httpClient = c.getHTTPClient()

	res, err := httpClient.Do(r)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.ServerUnavailableError, err)
		return
	}
	statusCode = res.StatusCode
	statusText = res.Status

	defer res.Body.Close()
	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		err = fmt.Errorf("%w: %v", verror.ServerError, err)
	}
	// Do not enable trace in production
	trace := false // IMPORTANT: sensitive information can be diclosured
	// I hope you know what are you doing
	if trace {
		log.Println("#################")
		if method == "POST" {
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

func parseUserDetailsResult(expectedStatusCode int, httpStatusCode int, httpStatus string, body []byte) (*userDetails, error) {
	if httpStatusCode == expectedStatusCode {
		return parseUserDetailsData(body)
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

func parseUserDetailsData(b []byte) (*userDetails, error) {
	var data userDetails
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return &data, nil
}

func parseZoneConfigurationResult(httpStatusCode int, httpStatus string, body []byte) (*zone, error) {
	switch httpStatusCode {
	case http.StatusOK:
		return parseZoneConfigurationData(body)
	case http.StatusBadRequest:
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

func parseZoneConfigurationData(b []byte) (*zone, error) {
	var data zone
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return &data, nil
}

func parseCertificateTemplate(httpStatusCode int, httpStatus string, body []byte) (*certificateTemplate, error) {
	ct := certificateTemplate{}
	if httpStatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: unexpected status code on Venafi Cloud policy read. Status: %s\n", verror.ServerError, httpStatus)
	}
	// todo: better error parsing
	err := json.Unmarshal(body, &ct)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}
	return &ct, nil
}

func parseCertificateRequestResult(httpStatusCode int, httpStatus string, body []byte) (*certificateRequestResponse, error) {
	switch httpStatusCode {
	case http.StatusCreated:
		return parseCertificateRequestData(body)
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

func parseCertificateRequestData(b []byte) (*certificateRequestResponse, error) {
	var data certificateRequestResponse
	err := json.Unmarshal(b, &data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", verror.ServerError, err)
	}

	return &data, nil
}

func newPEMCollectionFromResponse(data []byte, chainOrder certificate.ChainOption) (*certificate.PEMCollection, error) {
	return certificate.PEMCollectionFromBytes(data, chainOrder)
}

func certThumprint(asn1 []byte) string {
	h := sha1.Sum(asn1)
	return strings.ToUpper(fmt.Sprintf("%x", h))
}
