package endpoint

import (
	"github.com/Venafi/vcert/v5/pkg/domain"
	"time"
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

type ProvisioningOptions interface {
	GetType() string
}
