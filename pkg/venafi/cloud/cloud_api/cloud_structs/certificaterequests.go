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

// RESP: POST outagedetection/v1/certificaterequests
type CertificateRequestResponse struct {
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

// REQ: POST outagedetection/v1/certificaterequests
type CertificateRequest struct {
	CSR                      string                       `json:"certificateSigningRequest,omitempty"`
	ApplicationId            string                       `json:"applicationId,omitempty"`
	TemplateId               string                       `json:"certificateIssuingTemplateId,omitempty"`
	CertificateOwnerUserId   string                       `json:"certificateOwnerUserId,omitempty"`
	ExistingCertificateId    string                       `json:"existingCertificateId,omitempty"`
	ApiClientInformation     CertificateRequestClientInfo `json:"apiClientInformation,omitempty"`
	CertificateUsageMetadata []CertificateUsageMetadata   `json:"certificateUsageMetadata,omitempty"`
	ReuseCSR                 bool                         `json:"reuseCSR,omitempty"`
	ValidityPeriod           string                       `json:"validityPeriod,omitempty"`
	IsVaaSGenerated          bool                         `json:"isVaaSGenerated,omitempty"`
	CsrAttributes            CsrAttributes                `json:"csrAttributes,omitempty"`
	ApplicationServerTypeId  string                       `json:"applicationServerTypeId,omitempty"`
}

type CertificateRequestClientInfo struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type CertificateUsageMetadata struct {
	AppName            string `json:"appName,omitempty"`
	NodeName           string `json:"nodeName,omitempty"`
	AutomationMetadata string `json:"automationMetadata,omitempty"`
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

type SubjectAlternativeNamesByType struct {
	DnsNames                   []string `json:"dnsNames,omitempty"`
	IpAddresses                []string `json:"ipAddresses,omitempty"`
	Rfc822Names                []string `json:"rfc822Names,omitempty"`
	UniformResourceIdentifiers []string `json:"uniformResourceIdentifiers,omitempty"`
}

type KeyTypeParameters struct {
	KeyType   string  `json:"keyType,omitempty"`
	KeyLength *int    `json:"keyLength,omitempty"`
	KeyCurve  *string `json:"keyCurve,omitempty"`
}

// RESP: GET outagedetection/v1/certificaterequests/%s
type CertificateStatus struct {
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
