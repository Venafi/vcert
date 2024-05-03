package endpoint

type ProvisioningRequest struct {
	CertificateId *string
	PickupId      *string
	KeystoreId    *string
	KeystoreName  *string
	ProviderName  *string
}

type ProvisioningMetadata interface {
	GetAwsMetadata() AwsMetadata
	GetAzureMetadata() AzureMetadata
	GetGcpMetadata() GcpMetadata
}

type AwsMetadata interface {
	GetARN() string
}

type AzureMetadata interface {
	GetAKVID() string
	GetCertificateName() string
	GetVersion() string
}

type GcpMetadata interface {
	GetGCPID() string
	GetCertificateName() string
}

//type CertificateProvisioningOptions struct {
//	Options cloudkeystores.CertificateProvisioningOptionsInput `json:"options"`
//}

type ProvisioningOptions interface {
	GetType() string
}
