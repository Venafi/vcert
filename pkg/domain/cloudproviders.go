package domain

import "github.com/google/uuid"

type CloudProviderStatus int

const (
	CloudProviderStatusValidated = iota
	CloudProviderStatusNotValidated

	CloudProviderStatusValidatedStr    = "VALIDATED"
	CloudProviderStatusNotValidatedStr = "NOT_VALIDATED"
	CloudProviderStatusUnknownStr      = "UNKNOWN"
)

func (cps CloudProviderStatus) String() string {
	switch cps {
	case CloudProviderStatusValidated:
		return CloudProviderStatusValidatedStr
	case CloudProviderStatusNotValidated:
		return CloudProviderStatusNotValidatedStr
	default:
		return CloudProviderStatusUnknownStr
	}
}

type CloudProviderType int

const (
	CloudProviderTypeAWS = iota
	CloudProviderTypeAzure
	CloudProviderTypeGCP

	CloudProviderTypeAWSStr     = "AWS"
	CloudProviderTypeAzureStr   = "AZURE"
	CloudProviderTypeGCPStr     = "GCP"
	CloudProviderTypeUnknownStr = "UNKNOWN"
)

func (cps CloudProviderType) String() string {
	switch cps {
	case CloudProviderTypeAWS:
		return CloudProviderTypeAWSStr
	case CloudProviderTypeAzure:
		return CloudProviderTypeAzureStr
	case CloudProviderTypeGCP:
		return CloudProviderTypeGCPStr
	default:
		return CloudProviderTypeUnknownStr
	}
}

type CloudProvider struct {
	ID             string
	Name           string
	Type           string
	Status         string
	StatusDetails  string
	KeystoresCount int
}

type GetCloudProviderRequest struct {
	Name   string
	Status CloudProviderStatus
	Type   CloudProviderType
}

type CloudKeystore struct {
	ID                     string
	Name                   string
	Type                   string
	MachineIdentitiesCount int
}

type ProvisioningResponse struct {
	WorkflowId   string
	WorkflowName string
}

type GetCloudKeystoreRequest struct {
	CloudProviderID   *string
	CloudProviderName *string
	CloudKeystoreID   *string
	CloudKeystoreName *string
}

type MachineIdentityStatus int

const (
	MachineIdentityStatusUnknown MachineIdentityStatus = iota
	MachineIdentityStatusNew
	MachineIdentityStatusPending
	MachineIdentityStatusInstalled
	MachineIdentityStatusDiscovered
	MachineIdentityStatusValidated
	MachineIdentityStatusMissing
	MachineIdentityStatusFailed

	MachineIdentityStatusUnknownStr    = "UNKNOWN"
	MachineIdentityStatusNewStr        = "NEW"
	MachineIdentityStatusPendingStr    = "PENDING"
	MachineIdentityStatusInstalledStr  = "INSTALLED"
	MachineIdentityStatusDiscoveredStr = "DISCOVERED"
	MachineIdentityStatusValidatedStr  = "VALIDATED"
	MachineIdentityStatusMissingStr    = "MISSING"
	MachineIdentityStatusFailedStr     = "FAILED"

	CloudMetadataACM     = "ACM"
	CloudMetadataGCM     = "GCM"
	CloudMetadataAKV     = "AKV"
	CloudMetadataUnknown = "UNKNOWN"
)

func (mis MachineIdentityStatus) String() string {
	switch mis {
	case MachineIdentityStatusNew:
		return MachineIdentityStatusNewStr
	case MachineIdentityStatusPending:
		return MachineIdentityStatusPendingStr
	case MachineIdentityStatusInstalled:
		return MachineIdentityStatusInstalledStr
	case MachineIdentityStatusDiscovered:
		return MachineIdentityStatusDiscoveredStr
	case MachineIdentityStatusValidated:
		return MachineIdentityStatusValidatedStr
	case MachineIdentityStatusMissing:
		return MachineIdentityStatusMissingStr
	case MachineIdentityStatusFailed:
		return MachineIdentityStatusFailedStr
	default:
		return MachineIdentityStatusUnknownStr
	}
}

type CertificateCloudMetadata struct {
	values map[string]interface{}
}

func NewCertificateCloudMetadata(values map[string]interface{}) CertificateCloudMetadata {
	return CertificateCloudMetadata{
		values: values,
	}
}

func (ccm *CertificateCloudMetadata) GetType() string {
	typ := ccm.GetValue("__typename")
	if typ == nil {
		return CloudMetadataUnknown
	}
	switch typ {
	case "AWSCertificateMetadata":
		return CloudMetadataACM
	case "AzureCertificateMetadata":
		return CloudMetadataAKV
	case "GCPCertificateMetadata":
		return CloudMetadataGCM
	default:
		return CloudMetadataUnknown
	}
}

func (ccm *CertificateCloudMetadata) GetMetadata() map[string]interface{} {
	return ccm.values
}

func (ccm *CertificateCloudMetadata) GetValue(key string) interface{} {
	if key == "" {
		return nil
	}
	if ccm.values == nil {
		return nil
	}
	return ccm.values[key]
}

type CloudMachineIdentity struct {
	ID                uuid.UUID
	CloudKeystoreID   uuid.UUID
	CloudKeystoreName string
	CloudProviderID   uuid.UUID
	CloudProviderName string
	CertificateID     uuid.UUID
	Metadata          *CertificateCloudMetadata
	Status            MachineIdentityStatus
	StatusDetails     string
}

type GetCloudMachineIdentityRequest struct {
	KeystoreID        *string
	MachineIdentityID *string
	Fingerprints      []string
	NewlyDiscovered   *bool
	Metadata          *string
}
