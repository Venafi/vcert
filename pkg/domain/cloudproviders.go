package domain

import "github.com/google/uuid"

type CloudProvider struct {
	ID             string
	Name           string
	Type           string
	Status         string
	StatusDetails  string
	KeystoresCount int
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

	CloudMetadataACM     = "AWS"
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

func GetMachineIdentityStatus(status string) MachineIdentityStatus {
	switch status {
	case MachineIdentityStatusNewStr:
		return MachineIdentityStatusNew
	case MachineIdentityStatusPendingStr:
		return MachineIdentityStatusPending
	case MachineIdentityStatusInstalledStr:
		return MachineIdentityStatusInstalled
	case MachineIdentityStatusDiscoveredStr:
		return MachineIdentityStatusDiscovered
	case MachineIdentityStatusValidatedStr:
		return MachineIdentityStatusValidated
	case MachineIdentityStatusMissingStr:
		return MachineIdentityStatusMissing
	case MachineIdentityStatusFailedStr:
		return MachineIdentityStatusFailed
	default:
		return MachineIdentityStatusUnknown
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
		return CloudMetadataGCM
	case "GCPCertificateMetadata":
		return CloudMetadataAKV
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
