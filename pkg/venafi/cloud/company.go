/*
 * Copyright Venafi, Inc. and CyberArk Software Ltd. ("CyberArk")
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
	"time"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

type company struct {
	ID                 string    `json:"id,omitempty"`
	Name               string    `json:"name,omitempty"`
	CompanyType        string    `json:"companyType,omitempty"`
	Active             bool      `json:"active,omitempty"`
	CreationDateString string    `json:"creationDate,omitempty"`
	CreationDate       time.Time `json:"-"`
	Domains            []string  `json:"domains,omitempty"`
}

type zone struct {
	ID                           string    `json:"id,omitempty"`
	CompanyID                    string    `json:"companyId,omitempty"`
	Tag                          string    `json:"tag,omitempty"`
	ZoneType                     string    `json:"zoneType,omitempty"`
	SystemGenerated              bool      `json:"systemGenerated,omitempty"`
	CreationDateString           string    `json:"creationDate,omitempty"`
	CreationDate                 time.Time `json:"-"`
	CertificateIssuingTemplateId string    `json:"certificateIssuingTemplateId"`
}

func getZoneConfiguration(policy *certificateTemplate) (zoneConfig *endpoint.ZoneConfiguration) {
	zoneConfig = endpoint.NewZoneConfiguration()
	if policy == nil {
		return
	}
	zoneConfig.Policy = policy.toPolicy()
	policy.toZoneConfig(zoneConfig)
	return
}
