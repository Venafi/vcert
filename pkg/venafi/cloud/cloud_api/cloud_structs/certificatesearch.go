/*
 * Copyright 2022 Venafi, Inc.
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

package cloud_structs

// REQ: POST outagedetection/v1/certificatesearch
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
	Field    string      `json:"field"`
	Operator Operator    `json:"operator"`
	Value    interface{} `json:"value,omitempty"`
	Values   interface{} `json:"values,omitempty"`
}

type Operator string

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

type Paging struct {
	PageNumber int `json:"pageNumber"`
	PageSize   int `json:"pageSize"`
}

// RESP: POST outagedetection/v1/certificatesearch
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
	ApplicationIds                []string            `json:"applicationIds"`
	/* ... and many more fields ... */
}
