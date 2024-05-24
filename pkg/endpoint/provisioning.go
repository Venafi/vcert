package endpoint

import (
	"time"

	"github.com/Venafi/vcert/v5/pkg/domain"
)

type ProvisioningRequest struct {
	CertificateID *string
	PickupID      *string
	KeystoreID    *string
	KeystoreName  *string
	ProviderName  *string
	Timeout       time.Duration
	Keystore      *domain.CloudKeystore
}

type ProvisioningMetadata interface {
	GetAWSCertificateMetadata() AWSCertificateMetadata
	GetAzureCertificateMetadata() AzureCertificateMetadata
	GetGCPCertificateMetadata() GCPCertificateMetadata
	GetMachineIdentityMetadata() MachineIdentityMetadata
}

type AWSCertificateMetadata interface {
	GetARN() string
}

type AzureCertificateMetadata interface {
	GetID() string
	GetName() string
	GetVersion() string
}

type GCPCertificateMetadata interface {
	GetID() string
	GetName() string
}

type MachineIdentityMetadata interface {
	GetID() string
	GetActionType() string
}

type ProvisioningOptions interface {
	GetType() string
}
