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
	"fmt"
	"log"
	"time"
)

const (
	RevocationSubmittedFormattedMessage          = "The revocation for the certificate ID: %q Thumbprint: %q was successfully submitted."
	RevocationFailedFormattedMessage             = "failed to revoke certificate: ID: %q Thumbprint: %q"
	RevocationFailedWithErrorFormattedMessage    = "failed to revoke certificate: ID: %q Thumbprint: %q Error: %w"
	RevocationApprovalPendingFormattedMessage    = "The revocation for the certificate ID: %q Thumbprint: %q is pending for approval."
	RevocationRejectedFormattedMessage           = "The revocation for the certificate ID: %q Thumbprint: %q was rejected."
	RevocationRejectedWithReasonFormattedMessage = "The revocation for the certificate ID: %q Thumbprint: %q was rejected. Reason: %s."
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
	ID              string
	Thumbprint      string
	Status          string //The possible values are SUBMITTED, FAILED, PENDING_APPROVAL, PENDING_FINAL_APPROVAL, REJECTED_APPROVAL
	RejectionReason string
	Error           error
}

func (r *RevocationRequestResponseCloud) ToLog(logger *log.Logger) error {

	switch r.Status {
	case "SUBMITTED":
		logger.Printf(RevocationSubmittedFormattedMessage, r.ID, r.Thumbprint)
	case "FAILED":
		if r.Error != nil {
			return fmt.Errorf(RevocationFailedWithErrorFormattedMessage, r.ID, r.Thumbprint, r.Error)
		}
		return fmt.Errorf(RevocationFailedFormattedMessage, r.ID, r.Thumbprint)
	case "PENDING_APPROVAL", "PENDING_FINAL_APPROVAL":
		logger.Printf(RevocationApprovalPendingFormattedMessage, r.ID, r.Thumbprint)
	case "REJECTED_APPROVAL":
		if r.RejectionReason != "" {
			logger.Printf(RevocationRejectedWithReasonFormattedMessage, r.ID, r.Thumbprint, r.RejectionReason)
		} else {
			logger.Printf(RevocationRejectedFormattedMessage, r.ID, r.Thumbprint)
		}
	default:
		if r.Error != nil {
			return fmt.Errorf(RevocationFailedWithErrorFormattedMessage, r.ID, r.Thumbprint, r.Error)
		}
	}
	return nil
}
