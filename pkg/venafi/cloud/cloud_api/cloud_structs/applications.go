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

// REQ: POST outagedetection/v1/applications
// REQ: PUT outagedetection/v1/applications/%s
type Application struct {
	OwnerIdsAndTypes                     []OwnerIdAndType  `json:"ownerIdsAndTypes"`
	Name                                 string            `json:"name"`
	Description                          string            `json:"description"`
	Fqdns                                []string          `json:"fqdns"`
	InternalFqdns                        []string          `json:"internalFqdns"`
	InternalIpRanges                     []string          `json:"internalIpRanges"`
	ExternalIpRanges                     []string          `json:"externalIpRanges"`
	InternalPorts                        []string          `json:"internalPorts"`
	FullyQualifiedDomainNames            []string          `json:"fullyQualifiedDomainNames"`
	IpRanges                             []string          `json:"ipRanges"`
	Ports                                []string          `json:"ports"`
	CertificateIssuingTemplateAliasIdMap map[string]string `json:"certificateIssuingTemplateAliasIdMap"`
	StartTargetedDiscovery               bool              `json:"startTargetedDiscovery"`
}

// RESP: GET outagedetection/v1/applications/name/%s
type ApplicationDetails struct {
	Id                                   string            `json:"id,omitempty"`
	CertificateIssuingTemplateAliasIdMap map[string]string `json:"certificateIssuingTemplateAliasIdMap,omitempty"`
	CompanyId                            string            `json:"companyId,omitempty"`
	Name                                 string            `json:"name,omitempty"`
	Description                          string            `json:"description,omitempty"`
	OwnerIdsAndTypes                     []OwnerIdAndType  `json:"ownerIdsAndTypes,omitempty"`
	InternalFqDns                        []string          `json:"internalFqDns,omitempty"`
	ExternalIpRanges                     []string          `json:"externalIpRanges,omitempty"`
	InternalIpRanges                     []string          `json:"internalIpRanges,omitempty"`
	InternalPorts                        []string          `json:"internalPorts,omitempty"`
	FullyQualifiedDomainNames            []string          `json:"fullyQualifiedDomainNames,omitempty"`
	IpRanges                             []string          `json:"ipRanges,omitempty"`
	Ports                                []string          `json:"ports,omitempty"`
	FqDns                                []string          `json:"fqDns,omitempty"`
}
