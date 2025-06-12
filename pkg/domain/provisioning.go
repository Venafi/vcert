package domain

import (
	"time"
)

type ProvisioningRequest struct {
	MachineIdentityID *string
	CertificateID     *string
	PickupID          *string
	KeystoreID        *string
	KeystoreName      *string
	ProviderName      *string
	Timeout           time.Duration
	Keystore          *CloudKeystore
}

type ProvisioningMetadata struct {
	CloudKeystoreType         CloudKeystoreType
	CertificateID             string
	CertificateName           string
	CertificateVersion        string
	MachineIdentityID         string
	MachineIdentityActionType string
}

type ProvisioningOptions struct {
	// for ACM only
	ARN string
	// for AKV and GCM only
	CloudCertificateName string
	//GCM Certificate Scope
	GCMCertificateScope GCMCertificateScope
}
