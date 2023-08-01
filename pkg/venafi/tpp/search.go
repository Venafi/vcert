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
	"crypto/sha1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
)

type SearchRequest []string

type ConfigReadDNRequest struct {
	ObjectDN      string `json:",omitempty"`
	AttributeName string `json:",omitempty"`
}

type ConfigReadDNResponse struct {
	Result int      `json:",omitempty"`
	Values []string `json:",omitempty"`
}

type CertificateDetailsResponse struct {
	CustomFields []struct {
		Name  string
		Value []string
	}
	Consumers []string
	Disabled  bool `json:",omitempty"`
}

func (c *Connector) searchCertificatesByFingerprint(fp string) (*certificate.CertSearchResponse, error) {
	fp = strings.Replace(fp, ":", "", -1)
	fp = strings.Replace(fp, ".", "", -1)
	fp = strings.ToUpper(fp)

	var req certificate.SearchRequest
	req = append(req, fmt.Sprintf("Thumbprint=%s", fp))

	return c.SearchCertificates(&req)
}

func (c *Connector) configReadDN(req ConfigReadDNRequest) (resp ConfigReadDNResponse, err error) {

	statusCode, status, body, err := c.request("POST", urlResourceConfigReadDn, req)
	if err != nil {
		return resp, err
	}

	if statusCode == http.StatusOK {
		err = json.Unmarshal(body, &resp)
		if err != nil {
			return resp, err
		}
	} else {
		return resp, fmt.Errorf("unexpected status code on %s. Status: %s", urlResourceConfigReadDn, status)
	}

	return resp, nil
}

func (c *Connector) searchCertificateDetails(guid string) (*CertificateDetailsResponse, error) {
	var err error

	url := fmt.Sprintf("%s%s", urlResourceCertificateSearch, guid)
	statusCode, _, body, err := c.request("GET", urlResource(url), nil)
	if err != nil {
		return nil, err
	}
	return parseCertificateDetailsResponse(statusCode, body)
}

func parseCertificateDetailsResponse(statusCode int, body []byte) (searchResult *CertificateDetailsResponse, err error) {
	switch statusCode {
	case http.StatusOK:
		var searchResult = &CertificateDetailsResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse search results: %s, body: %s", err, body)
		}
		return searchResult, nil
	default:
		if body != nil {
			return nil, NewResponseError(body)
		} else {
			return nil, fmt.Errorf("Unexpected status code on certificate search. Status: %d", statusCode)
		}
	}
}

func ParseCertificateSearchResponse(httpStatusCode int, body []byte) (searchResult *certificate.CertSearchResponse, err error) {
	switch httpStatusCode {
	case http.StatusOK:
		var searchResult = &certificate.CertSearchResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse search results: %s, body: %s", err, body)
		}
		return searchResult, nil
	default:
		if body != nil {
			return nil, NewResponseError(body)
		} else {
			return nil, fmt.Errorf("Unexpected status code on certificate search. Status: %d", httpStatusCode)
		}
	}
}

type CertificateSearchResponse struct {
	Certificates []CertificateSearchInfo `json:"Certificates"`
	Count        int                     `json:"TotalCount"`
}

type CertificateSearchInfo struct {
	CreatedOn   string
	DN          string
	Guid        string
	Name        string
	ParentDn    string
	SchemaClass string
	X509        certificate.CertificateInfo
}

func parseSearchCertificateResponse(httpStatusCode int, body []byte) (certificates *CertificateSearchResponse, err error) {
	switch httpStatusCode {
	case http.StatusOK:
		var searchResult = &CertificateSearchResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse search results: %s, body: %s", err, body)
		}
		return searchResult, nil
	default:
		if body != nil {
			return nil, NewResponseError(body)
		} else {
			return nil, fmt.Errorf("Unexpected status code on certificate search. Status: %d", httpStatusCode)
		}
	}
}

func formatSearchCertificateArguments(cn string, sans *certificate.Sans, certMinTimeLeft time.Duration) string {
	// get future (or past) date for certificate validation
	date := time.Now().Add(certMinTimeLeft)
	// create request arguments
	req := make([]string, 0)

	if cn != "" {
		req = append(req, fmt.Sprintf("CN=%s", cn))
	}

	if sans != nil && sans.DNS != nil {
		req = append(req, fmt.Sprintf("SAN-DNS=%s", strings.Join(sans.DNS, ",")))
	}

	req = append(req, fmt.Sprintf("ValidToGreater=%s", neturl.QueryEscape(date.Format(time.RFC3339))))

	return strings.Join(req, "&")
}

func calcThumbprint(cert string) string {
	p, _ := pem.Decode([]byte(cert))
	h := sha1.New()
	h.Write(p.Bytes)
	buf := h.Sum(nil)
	return strings.ToUpper(fmt.Sprintf("%x", buf))
}
