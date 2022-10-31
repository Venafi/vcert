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

import (
	"time"
)

// RESP: GET outagedetection/v1/certificateissuingtemplates
// RESP: POST outagedetection/v1/certificateissuingtemplates
type CertificateTemplates struct {
	CertificateTemplates []CertificateTemplate `json:"certificateIssuingTemplates"`
}

// RESP: PUT outagedetection/v1/certificateissuingtemplates/%s
// RESP: GET outagedetection/v1/applications/%s/certificateissuingtemplates/%s
type CertificateTemplate struct {
	ID                                  string `json:"id,omitempty"`
	CompanyID                           string `json:"companyId,omitempty"`
	CertificateAuthority                string `json:"certificateAuthority"`
	Name                                string `json:"name,omitempty"`
	CertificateAuthorityAccountId       string `json:"certificateAuthorityAccountId"`
	CertificateAuthorityProductOptionId string `json:"certificateAuthorityProductOptionId"`
	Product                             struct {
		CertificateAuthority string `json:"certificateAuthority"`
		ProductName          string `json:"productName"`
	} `json:"product"`
	Priority                            int       `json:"priority"`
	SystemGenerated                     bool      `json:"systemGenerated,omitempty"`
	CreationDateString                  string    `json:"creationDate,omitempty"`
	CreationDate                        time.Time `json:"-"`
	ModificationDateString              string    `json:"modificationDate"`
	ModificationDate                    time.Time `json:"-"`
	Status                              string    `json:"status"`
	Reason                              string    `json:"reason"`
	SubjectCNRegexes                    []string  `json:"subjectCNRegexes,omitempty"`
	SubjectORegexes                     []string  `json:"subjectORegexes,omitempty"`
	SubjectOURegexes                    []string  `json:"subjectOURegexes,omitempty"`
	SubjectSTRegexes                    []string  `json:"subjectSTRegexes,omitempty"`
	SubjectLRegexes                     []string  `json:"subjectLRegexes,omitempty"`
	SubjectCValues                      []string  `json:"subjectCValues,omitempty"`
	SANRegexes                          []string  `json:"sanRegexes,omitempty"`
	SanRfc822NameRegexes                []string  `json:"sanRfc822NameRegexes,omitempty"`
	SanIpAddressRegexes                 []string  `json:"sanIpAddressRegexes,omitempty"`
	SanUniformResourceIdentifierRegexes []string  `json:"sanUniformResourceIdentifierRegexes,omitempty"`
	KeyTypes                            []KeyType `json:"keyTypes,omitempty"`
	KeyReuse                            bool      `json:"keyReuse,omitempty"`
	RecommendedSettings                 struct {
		SubjectOValue, SubjectOUValue,
		SubjectSTValue, SubjectLValue,
		SubjectCValue string
		Key struct {
			Type   string
			Length int
			Curve  string
		}
		keyReuse bool
	}
	ValidityPeriod              string `json:"validityPeriod,omitempty"`
	CsrUploadAllowed            bool   `json:"csrUploadAllowed"`
	KeyGeneratedByVenafiAllowed bool   `json:"keyGeneratedByVenafiAllowed"`
}

// REQ: PUT outagedetection/v1/certificateissuingtemplates/%s
// REQ: POST outagedetection/v1/certificateissuingtemplates
type CloudPolicyRequest struct {
	Name                                string               `json:"name"`
	CertificateAuthority                string               `json:"certificateAuthority"`
	CertificateAuthorityProductOptionId string               `json:"certificateAuthorityProductOptionId"`
	Product                             Product              `json:"product"`
	TrackingData                        *TrackingData        `json:"trackingData"`
	SubjectCNRegexes                    []string             `json:"subjectCNRegexes"`
	SubjectORegexes                     []string             `json:"subjectORegexes"`
	SubjectOURegexes                    []string             `json:"subjectOURegexes"`
	SubjectLRegexes                     []string             `json:"subjectLRegexes"`
	SubjectSTRegexes                    []string             `json:"subjectSTRegexes"`
	SubjectCValues                      []string             `json:"subjectCValues"`
	SanRegexes                          []string             `json:"sanRegexes"`
	SanIpAddressRegexes                 []string             `json:"sanIpAddressRegexes"`
	SanRfc822NameRegexes                []string             `json:"sanRfc822NameRegexes"`
	SanUniformResourceIdentifierRegexes []string             `json:"sanUniformResourceIdentifierRegexes"`
	KeyTypes                            []KeyType            `json:"keyTypes"`
	KeyReuse                            *bool                `json:"keyReuse"`
	RecommendedSettings                 *RecommendedSettings `json:"recommendedSettings"`
	CsrUploadAllowed                    bool                 `json:"csrUploadAllowed"`
	KeyGeneratedByVenafiAllowed         bool                 `json:"keyGeneratedByVenafiAllowed"`
}

type Product struct {
	CertificateAuthority string  `json:"certificateAuthority"`
	ProductName          string  `json:"productName"`
	ValidityPeriod       string  `json:"validityPeriod"`
	HashAlgorithm        *string `json:"hashAlgorithm,omitempty"`
	AutoRenew            *bool   `json:"autoRenew,omitempty"`
	OrganizationId       *int64  `json:"organizationId,omitempty"`
}

type KeyType struct {
	KeyType    string   `json:"keyType"`
	KeyLengths []int    `json:"keyLengths,omitempty"`
	KeyCurves  []string `json:"keyCurves,omitempty"`
}

type TrackingData struct {
	CertificateAuthority string `json:"certificateAuthority"`
	RequesterName        string `json:"requesterName"`
	RequesterEmail       string `json:"requesterEmail"`
	RequesterPhone       string `json:"requesterPhone"`
}

type RecommendedSettings struct {
	SubjectCNRegexes []string `json:"subjectCNRegexes"`
	SubjectOValue    *string  `json:"subjectOValue"`
	SubjectOUValue   *string  `json:"subjectOUValue"`
	SubjectLValue    *string  `json:"subjectLValue"`
	SubjectSTValue   *string  `json:"subjectSTValue"`
	SubjectCValue    *string  `json:"subjectCValue"`
	SanRegexes       []string `json:"sanRegexes"`
	Key              *Key     `json:"key"`
}

type Key struct {
	Type   string `json:"type"`
	Length int    `json:"length,omitempty"`
	Curve  string `json:"curve,omitempty"`
}
