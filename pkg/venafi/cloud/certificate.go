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

import (
	"fmt"
	"log"
	"time"
)

type VenafiCertificate struct {
	ID                   string    `json:"id,omitempty"`
	CertificateStatus    string    `json:"certificateStatus,omitempty"`
	CertificateRequestId string    `json:"certificateRequestId,omitempty"`
	DekHash              string    `json:"dekHash,omitempty"`
	Fingerprint          string    `json:"fingerprint,omitempty"`
	CertificateSource    string    `json:"certificateSource,omitempty"`
	ValidityEnd          time.Time `json:"validityEnd"`
}

type RevocationRequestResponseCloud struct {
	ID         string
	Thumbprint string
	Status     string
	Reason     string
	Error      error
}

func (r *RevocationRequestResponseCloud) ToLog(logger *log.Logger) error {

	if r.Error != nil {
		return fmt.Errorf("failed to revoke certificate: \n\t\tID: %s\n\t\tThumbprint: %s\n\t\t%w", r.ID, r.Thumbprint, r.Error)
	}

	var reasonString string
	if r.Reason != "" {
		reasonString = fmt.Sprintf("\n\t\tReason: %s", r.Reason)
	}

	logger.Printf("Revocation request result: \n\t\tID: %s\n\t\tThumbprint: %s\n\t\tStatus: %s%s", r.ID, r.Thumbprint, r.Status, reasonString)

	return nil
}
