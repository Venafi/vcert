/*
 * Copyright 2024 Venafi, Inc.
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

import "time"

type VenafiCertificate struct {
	ID                   string    `json:"id,omitempty"`
	CertificateStatus    string    `json:"certificateStatus,omitempty"`
	CertificateRequestId string    `json:"certificateRequestId,omitempty"`
	DekHash              string    `json:"dekHash,omitempty"`
	Fingerprint          string    `json:"fingerprint,omitempty"`
	CertificateSource    string    `json:"certificateSource,omitempty"`
	ValidityEnd          time.Time `json:"validityEnd"`
}
