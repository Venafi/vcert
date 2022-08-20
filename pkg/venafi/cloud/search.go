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
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/verror"
)

type SearchRequest struct {
	Expression *Expression  `json:"expression"`
	Ordering   *interface{} `json:"ordering,omitempty"`
	Paging     *Paging      `json:"paging,omitempty"`
	// ordering is not used here so far
	// "ordering": {"orders": [{"direction": "ASC", "field": "subjectCN"},{"direction": "DESC", "field": "keyStrength"}]},
}

type Expression struct {
	Operator Operator  `json:"operator,omitempty"`
	Operands []Operand `json:"operands,omitempty"`
}

type Operand struct {
	Field    Field       `json:"field"`
	Operator Operator    `json:"operator"`
	Value    interface{} `json:"value"`
}

type Field string
type Operator string

type Paging struct {
	PageNumber int `json:"pageNumber"`
	PageSize   int `json:"pageSize"`
}

const (
	EQ    Operator = "EQ"
	FIND  Operator = "FIND"
	GT    Operator = "GT"
	GTE   Operator = "GTE"
	IN    Operator = "IN"
	LT    Operator = "LT"
	LTE   Operator = "LTE"
	MATCH Operator = "MATCH"
	AND   Operator = "AND"
)

type CertificateSearchResponse struct {
	Count        int           `json:"count"`
	Certificates []Certificate `json:"certificates"`
}

type Certificate struct {
	Id                            string              `json:"id"`
	ManagedCertificateId          string              `json:"managedCertificateId"`
	CertificateRequestId          string              `json:"certificateRequestId"`
	SubjectCN                     []string            `json:"subjectCN"`
	SubjectAlternativeNamesByType map[string][]string `json:"subjectAlternativeNamesByType"`
	SerialNumber                  string              `json:"serialNumber"`
	Fingerprint                   string              `json:"fingerprint"`
	ValidityStart                 string              `json:"validityStart"`
	ValidityEnd                   string              `json:"validityEnd"`
	/* ... and many more fields ... */
}

func (c Certificate) ToCertificateInfo() certificate.CertificateInfo {
	var cn string
	if len(c.SubjectCN) > 0 {
		cn = c.SubjectCN[0]
	}

	start, err := time.Parse(time.RFC3339, c.ValidityStart)
	if err != nil { //we just print the error, and let the user know.
		log.Println(err)
	}

	end, err := time.Parse(time.RFC3339, c.ValidityEnd)
	if err != nil { //we just print the error, and let the user know.
		log.Println(err)
	}

	ci := certificate.CertificateInfo{
		ID: c.Id,
		CN: cn,
		SANS: struct {
			DNS, Email, IP, URI, UPN []string
		}{
			c.SubjectAlternativeNamesByType["dNSName"],
			c.SubjectAlternativeNamesByType["rfc822Name"],
			c.SubjectAlternativeNamesByType["iPAddress"],
			c.SubjectAlternativeNamesByType["uniformResourceIdentifier"],
			[]string{}, // todo: find correct field
		},
		Serial:     c.SerialNumber,
		Thumbprint: c.Fingerprint,
		ValidFrom:  start,
		ValidTo:    end,
	}
	return ci
}

func ParseCertificateSearchResponse(httpStatusCode int, httpStatus string, body []byte) (searchResult *CertificateSearchResponse, err error) {
	switch httpStatusCode {
	case http.StatusOK:
		var searchResult = &CertificateSearchResponse{}
		err = json.Unmarshal(body, searchResult)
		if err != nil {
			return nil, fmt.Errorf("failed to parse search results: %s, body: %s", err, body)
		}
		return searchResult, nil
	default:
		verr := verror.VCertConnectorError{
			Platform:   "VaaS",
			Operation:  "certificate search",
			StatusCode: httpStatusCode,
			Status:     httpStatus,
		}

		if body == nil {
			return nil, verr
		}

		respErrors, err := parseResponseErrors(body)
		if err != nil {
			return nil, err
		}

		return nil, verror.VCertConnectorResponseError{
			VCertConnectorError: verr,
			ResponseErrors:      respErrors,
		}
	}
}
