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

import "time"

// REQ: POST outagedetection/v1/certificates
type ImportRequest struct {
	Certificates []ImportRequestCertInfo `json:"certificates"`
}

type ImportRequestCertInfo struct {
	Certificate              string                     `json:"certificate"`
	IssuerCertificates       []string                   `json:"issuerCertificates,omitempty"`
	ApplicationIds           []string                   `json:"applicationIds"`
	ApiClientInformation     ApiClientInformation       `json:"apiClientInformation,omitempty"`
	CertificateUsageMetadata []CertificateUsageMetadata `json:"certificateUsageMetadata,omitempty"`
}

type ApiClientInformation struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

// RESP: POST outagedetection/v1/certificates
type ImportResponse struct {
	CertificateInformations []importResponseCertInfo `json:"certificateInformations"`
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
	ApiClientInformation    ApiClientInformation `json:"apiClientInformation,omitempty"`
}
type OwnerIdAndType struct {
	OwnerId   string `json:"ownerId"`
	OwnerType string `json:"ownerType"`
}

// REQ: POST outagedetection/v1/certificates/%s/keystore
type KeyStoreRequest struct {
	ExportFormat                  string `json:"exportFormat,omitempty"`
	EncryptedPrivateKeyPassphrase string `json:"encryptedPrivateKeyPassphrase"`
	EncryptedKeystorePassphrase   string `json:"encryptedKeystorePassphrase"`
	CertificateLabel              string `json:"certificateLabel"`
}

// RESP: GET outagedetection/v1/certificates/%s
type ManagedCertificate struct {
	Id                   string `json:"id"`
	CompanyId            string `json:"companyId"`
	CertificateRequestId string `json:"certificateRequestId"`
	DekHash              string `json:"dekHash,omitempty"`
}
