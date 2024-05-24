package domain

import (
	"strings"

	"github.com/google/uuid"
)

type CloudProviderStatus int

const (
	CloudProviderStatusUnknown CloudProviderStatus = iota
	CloudProviderStatusValidated
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
	case CloudProviderStatusUnknown:
		fallthrough
	default:
		return CloudProviderStatusUnknownStr
	}
}

func GetCloudProviderStatus(status string) CloudProviderStatus {
	switch strings.ToUpper(status) {
	case CloudProviderStatusValidatedStr:
		return CloudProviderStatusValidated
	case CloudProviderStatusNotValidatedStr:
		return CloudProviderStatusNotValidated
	default:
		return CloudProviderStatusUnknown
	}
}

type CloudProviderType int

const (
	CloudProviderTypeUnknown CloudProviderType = iota
	CloudProviderTypeAWS
	CloudProviderTypeAzure
	CloudProviderTypeGCP

	CloudProviderTypeAWSStr     = "AWS"
	CloudProviderTypeAzureStr   = "AZURE"
	CloudProviderTypeGCPStr     = "GCP"
	CloudProviderTypeUnknownStr = "UNKNOWN"
)

func (cpt CloudProviderType) String() string {
	switch cpt {
	case CloudProviderTypeAWS:
		return CloudProviderTypeAWSStr
	case CloudProviderTypeAzure:
		return CloudProviderTypeAzureStr
	case CloudProviderTypeGCP:
		return CloudProviderTypeGCPStr
	case CloudProviderTypeUnknown:
		fallthrough
	default:
		return CloudProviderTypeUnknownStr
	}
}

type CloudProvider struct {
	ID             string
	Name           string
	Type           CloudProviderType
	Status         CloudProviderStatus
	StatusDetails  string
	KeystoresCount int
}

type GetCloudProviderRequest struct {
	Name   string
	Status CloudProviderStatus
	Type   CloudProviderType
}

type CloudKeystoreType int

const (
	CloudKeystoreTypeUnknown CloudKeystoreType = iota
	CloudKeystoreTypeACM
	CloudKeystoreTypeAKV
	CloudKeystoreTypeGCM

	CloudKeystoreTypeACMStr     = "ACM"
	CloudKeystoreTypeAKVStr     = "AKV"
	CloudKeystoreTypeGCMStr     = "GCM"
	CloudKeystoreTypeUnknownStr = "UNKNOWN"
)

func (ckt CloudKeystoreType) String() string {
	switch ckt {
	case CloudKeystoreTypeACM:
		return CloudKeystoreTypeACMStr
	case CloudKeystoreTypeAKV:
		return CloudKeystoreTypeAKVStr
	case CloudKeystoreTypeGCM:
		return CloudKeystoreTypeGCMStr
	case CloudKeystoreTypeUnknown:
		fallthrough
	default:
		return CloudKeystoreTypeUnknownStr
	}
}

type CloudKeystore struct {
	ID                     string
	Name                   string
	Type                   CloudKeystoreType
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
	case MachineIdentityStatusUnknown:
		fallthrough
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

func (ccm *CertificateCloudMetadata) GetKeystoreType() CloudKeystoreType {
	typ := ccm.GetValue("__typename")
	if typ == nil {
		return CloudKeystoreTypeUnknown
	}
	switch typ {
	case "AWSCertificateMetadata":
		return CloudKeystoreTypeACM
	case "AzureCertificateMetadata":
		return CloudKeystoreTypeAKV
	case "GCPCertificateMetadata":
		return CloudKeystoreTypeGCM
	default:
		return CloudKeystoreTypeUnknown
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
