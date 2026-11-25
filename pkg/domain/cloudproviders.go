package domain

import (
	"strings"
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
	// The configuration matching Type. Only populated by ListCloudProviders
	// and the create/update operations. The Azure secret is never returned.
	AWS   *CloudProviderAWSConfiguration
	Azure *CloudProviderAzureConfiguration
	GCP   *CloudProviderGCPConfiguration
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
	// The fields below are only populated by ListCloudKeystores and the
	// create/update operations
	CloudProviderID        string
	CloudProviderName      string
	ACM                    *CloudKeystoreACMConfiguration
	AKV                    *CloudKeystoreAKVConfiguration
	GCM                    *CloudKeystoreGCMConfiguration
	DiscoveryConfiguration *CloudDiscoveryConfiguration
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
	ID                string
	CloudKeystoreID   string
	CloudKeystoreName string
	CloudProviderID   string
	CloudProviderName string
	CertificateID     string
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

func GetCloudProviderType(providerType string) CloudProviderType {
	switch strings.ToUpper(providerType) {
	case CloudProviderTypeAWSStr:
		return CloudProviderTypeAWS
	case CloudProviderTypeAzureStr:
		return CloudProviderTypeAzure
	case CloudProviderTypeGCPStr:
		return CloudProviderTypeGCP
	default:
		return CloudProviderTypeUnknown
	}
}

func GetCloudKeystoreType(keystoreType string) CloudKeystoreType {
	switch strings.ToUpper(keystoreType) {
	case CloudKeystoreTypeACMStr:
		return CloudKeystoreTypeACM
	case CloudKeystoreTypeAKVStr:
		return CloudKeystoreTypeAKV
	case CloudKeystoreTypeGCMStr:
		return CloudKeystoreTypeGCM
	default:
		return CloudKeystoreTypeUnknown
	}
}

type GCPAuthorizationMethod int

const (
	GCPAuthorizationMethodUnknown GCPAuthorizationMethod = iota
	GCPAuthorizationMethodVenafiGeneratedKey
	GCPAuthorizationMethodWorkloadIdentityFederation

	GCPAuthorizationMethodVenafiGeneratedKeyStr         = "VENAFI_GENERATED_KEY"
	GCPAuthorizationMethodWorkloadIdentityFederationStr = "WORKLOAD_IDENTITY_FEDERATION"
	GCPAuthorizationMethodUnknownStr                    = "UNKNOWN"
)

func (m GCPAuthorizationMethod) String() string {
	switch m {
	case GCPAuthorizationMethodVenafiGeneratedKey:
		return GCPAuthorizationMethodVenafiGeneratedKeyStr
	case GCPAuthorizationMethodWorkloadIdentityFederation:
		return GCPAuthorizationMethodWorkloadIdentityFederationStr
	case GCPAuthorizationMethodUnknown:
		fallthrough
	default:
		return GCPAuthorizationMethodUnknownStr
	}
}

func GetGCPAuthorizationMethod(method string) GCPAuthorizationMethod {
	switch strings.ToUpper(method) {
	case GCPAuthorizationMethodVenafiGeneratedKeyStr:
		return GCPAuthorizationMethodVenafiGeneratedKey
	case GCPAuthorizationMethodWorkloadIdentityFederationStr:
		return GCPAuthorizationMethodWorkloadIdentityFederation
	default:
		return GCPAuthorizationMethodUnknown
	}
}

type CloudProviderAWSConfiguration struct {
	AccountID string
	Role      string
	// ExternalID is generated by the platform for the IAM role's trust policy.
	// It is ignored on create.
	ExternalID string
}

type CloudProviderAzureConfiguration struct {
	ApplicationID string
	DirectoryID   string
	Secret        string
}

type CloudProviderGCPConfiguration struct {
	ServiceAccountEmail            string
	ProjectNumber                  string
	WorkloadIdentityPoolID         string
	WorkloadIdentityPoolProviderID string
	AuthorizationMethod            GCPAuthorizationMethod
	// PublicKey is generated by the platform for the VENAFI_GENERATED_KEY
	// authorization method, to be uploaded to the service account. IssuerURL
	// is the platform's OIDC issuer for workload identity federation. Both are
	// ignored on create.
	PublicKey string
	IssuerURL string
}

// CreateCloudProviderRequest holds the data for a new cloud provider. Exactly one
// of AWS, Azure or GCP must be set and it must match Type.
type CreateCloudProviderRequest struct {
	Name   string
	Type   CloudProviderType
	TeamID string
	AWS    *CloudProviderAWSConfiguration
	Azure  *CloudProviderAzureConfiguration
	GCP    *CloudProviderGCPConfiguration
}

type CloudProviderAWSConfigurationUpdate struct {
	Role *string
}

type CloudProviderAzureConfigurationUpdate struct {
	ApplicationID *string
	DirectoryID   *string
	// Secret is required by the API whenever the Azure configuration is updated
	Secret string
}

type CloudProviderGCPConfigurationUpdate struct {
	ProjectNumber                  *string
	WorkloadIdentityPoolID         *string
	WorkloadIdentityPoolProviderID *string
	// AuthorizationMethod is left unchanged when set to GCPAuthorizationMethodUnknown
	AuthorizationMethod GCPAuthorizationMethod
}

// UpdateCloudProviderRequest holds the changes to apply to an existing cloud
// provider. ID and Type are required; nil fields are left unchanged.
type UpdateCloudProviderRequest struct {
	ID     string
	Type   CloudProviderType
	Name   *string
	TeamID *string
	AWS    *CloudProviderAWSConfigurationUpdate
	Azure  *CloudProviderAzureConfigurationUpdate
	GCP    *CloudProviderGCPConfigurationUpdate
}

type CloudProviderValidationResult struct {
	Status  CloudProviderStatus
	Details string
}

type CloudKeystoreACMConfiguration struct {
	Region    string
	AccountID string
}

type CloudKeystoreAKVConfiguration struct {
	KeyVaultName string
}

type CloudKeystoreGCMConfiguration struct {
	ProjectID string
	Location  string
}

type CloudDiscoveryConfiguration struct {
	ScheduleSpecification      string
	IncludeExpiredCertificates bool
	IncludeRevokedCertificates bool
}

// CloudDiscoveryOptions sets the discovery configuration of a cloud keystore.
// Nil fields are left unchanged on update, or take the server default on create.
// A ScheduleSpecification pointing to an empty string removes the schedule.
type CloudDiscoveryOptions struct {
	ScheduleSpecification      *string
	IncludeExpiredCertificates *bool
	IncludeRevokedCertificates *bool
}

// CreateCloudKeystoreRequest holds the data for a new cloud keystore. Exactly one
// of ACM, AKV or GCM must be set and it must match Type.
type CreateCloudKeystoreRequest struct {
	Name            string
	Type            CloudKeystoreType
	CloudProviderID string
	TeamID          string
	ACM             *CloudKeystoreACMConfiguration
	AKV             *CloudKeystoreAKVConfiguration
	GCM             *CloudKeystoreGCMConfiguration
	Discovery       *CloudDiscoveryOptions
}

// UpdateCloudKeystoreRequest holds the changes to apply to an existing cloud
// keystore. ID is required; nil fields are left unchanged.
type UpdateCloudKeystoreRequest struct {
	ID        string
	Name      *string
	TeamID    *string
	Discovery *CloudDiscoveryOptions
}

type ListCloudMachineIdentitiesRequest struct {
	KeystoreID string
}
