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
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"net/http"
	"strings"
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

type CertificateSearchResponse struct {
	Certificates []Certificate `json:"Certificates"`
	Count        int           `json:"TotalCount"`
}

type Certificate struct {
	//Id                   string   `json:"DN"`
	//ManagedCertificateId string   `json:"DN"`
	CertificateRequestId   string `json:"DN"`
	CertificateRequestGuid string `json:"Guid"`
	/*...and some more fields... */
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
		err := verror.VCertConnectorUnexpectedStatusError{Platform: "TPP"}
		err.Status = status;
		err.Operation = string(urlResourceConfigReadDn)
		return resp, err
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
			return nil, fmt.Errorf("failed to parse search results: %s, body: %s", err, body)
		}
		return searchResult, nil
	default:
		if body != nil {
			return nil, NewResponseError(body)
		} else {
			err := verror.VCertConnectorUnexpectedStatusError{Platform: "TPP", Operation: "certificate search"}
			err.StatusCode = statusCode;
			return nil, err
		}
	}
}

func ParseCertificateSearchResponse(httpStatusCode int, body []byte) (searchResult *certificate.CertSearchResponse, err error) {
	switch httpStatusCode {
	case http.StatusOK:
		var searchResult = &certificate.CertSearchResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, fmt.Errorf("failed to parse search results: %s, body: %s", err, body)
		}
		return searchResult, nil
	default:
		if body != nil {
			return nil, NewResponseError(body)
		} else {
			err := verror.VCertConnectorUnexpectedStatusError{Platform: "TPP", Operation: "certificate search"}
			err.StatusCode = httpStatusCode;
			return nil, err
		}
	}
}

func calcThumbprint(cert string) string {
	p, _ := pem.Decode([]byte(cert))
	h := sha1.New()
	h.Write(p.Bytes)
	buf := h.Sum(nil)
	return strings.ToUpper(fmt.Sprintf("%x", buf))
}
