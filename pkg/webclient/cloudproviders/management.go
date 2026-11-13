package cloudproviders

import (
	"context"
	"fmt"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/verror"
)

func (c *CloudProvidersClient) ListCloudProviders(ctx context.Context, request domain.GetCloudProviderRequest) ([]domain.CloudProvider, error) {
	status := cloudProviderStatusFromDomain(request.Status)
	providerType := cloudProviderTypeFromDomain(request.Type)
	var name *string
	if request.Name != "" {
		name = &request.Name
	}

	providers := make([]domain.CloudProvider, 0)
	var after *string
	for {
		resp, err := ListCloudProviders(ctx, c.graphqlClient, status, providerType, name, after)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cloud Providers: %w", err)
		}
		if resp == nil || resp.GetCloudProviders() == nil {
			return providers, nil
		}
		for _, node := range resp.GetCloudProviders().GetNodes() {
			providers = append(providers, node.CloudProviderFields.toDomain())
		}
		pageInfo := resp.GetCloudProviders().GetPageInfo()
		if pageInfo == nil || !pageInfo.GetHasNextPage() || pageInfo.GetEndCursor() == nil {
			return providers, nil
		}
		after = pageInfo.GetEndCursor()
	}
}

func (c *CloudProvidersClient) CreateCloudProvider(ctx context.Context, request domain.CreateCloudProviderRequest) (*domain.CloudProvider, error) {
	input, err := cloudProviderInputFromDomain(request)
	if err != nil {
		return nil, err
	}

	resp, err := CreateCloudProvider(ctx, c.graphqlClient, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Provider %s: %w", request.Name, err)
	}
	if resp == nil || resp.GetCreateCloudProvider() == nil {
		return nil, fmt.Errorf("failed to create Cloud Provider %s: empty response", request.Name)
	}

	cp := resp.GetCreateCloudProvider().CloudProviderFields.toDomain()
	return &cp, nil
}

func (c *CloudProvidersClient) UpdateCloudProvider(ctx context.Context, request domain.UpdateCloudProviderRequest) (*domain.CloudProvider, error) {
	input, err := cloudProviderUpdateInputFromDomain(request)
	if err != nil {
		return nil, err
	}

	resp, err := UpdateCloudProvider(ctx, c.graphqlClient, input)
	if err != nil {
		return nil, fmt.Errorf("failed to update Cloud Provider with ID %s: %w", request.ID, err)
	}
	if resp == nil || resp.GetUpdateCloudProvider() == nil {
		return nil, fmt.Errorf("failed to update Cloud Provider with ID %s: empty response", request.ID)
	}

	cp := resp.GetUpdateCloudProvider().CloudProviderFields.toDomain()
	return &cp, nil
}

func (c *CloudProvidersClient) DeleteCloudProvider(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("cloud provider ID cannot be empty")
	}
	resp, err := DeleteCloudProviders(ctx, c.graphqlClient, []string{id})
	if err != nil {
		return fmt.Errorf("failed to delete Cloud Provider with ID %s: %w", id, err)
	}
	if resp == nil || !resp.GetDeleteCloudProvider() {
		return fmt.Errorf("failed to delete Cloud Provider with ID %s", id)
	}
	return nil
}

func (c *CloudProvidersClient) ValidateCloudProvider(ctx context.Context, id string) (*domain.CloudProviderValidationResult, error) {
	if id == "" {
		return nil, fmt.Errorf("cloud provider ID cannot be empty")
	}
	resp, err := ValidateCloudProvider(ctx, c.graphqlClient, id)
	if err != nil {
		return nil, fmt.Errorf("failed to validate Cloud Provider with ID %s: %w", id, err)
	}
	if resp == nil || resp.GetValidateCloudProvider() == nil {
		return nil, fmt.Errorf("failed to validate Cloud Provider with ID %s: empty response", id)
	}

	result := resp.GetValidateCloudProvider()
	details := ""
	if result.GetDetails() != nil {
		details = *result.GetDetails()
	}
	return &domain.CloudProviderValidationResult{
		Status:  result.GetResult().toDomain(),
		Details: details,
	}, nil
}

func (c *CloudProvidersClient) ListCloudKeystores(ctx context.Context, request domain.GetCloudKeystoreRequest) ([]domain.CloudKeystore, error) {
	keystores := make([]domain.CloudKeystore, 0)
	var after *string
	for {
		resp, err := ListCloudKeystores(ctx, c.graphqlClient, request.CloudKeystoreID, request.CloudKeystoreName, request.CloudProviderID, request.CloudProviderName, after)
		if err != nil {
			return nil, fmt.Errorf("failed to list Cloud Keystores: %w", err)
		}
		if resp == nil || resp.GetCloudKeystores() == nil {
			return keystores, nil
		}
		for _, node := range resp.GetCloudKeystores().GetNodes() {
			keystores = append(keystores, node.CloudKeystoreFields.toDomain())
		}
		pageInfo := resp.GetCloudKeystores().GetPageInfo()
		if pageInfo == nil || !pageInfo.GetHasNextPage() || pageInfo.GetEndCursor() == nil {
			return keystores, nil
		}
		after = pageInfo.GetEndCursor()
	}
}

func (c *CloudProvidersClient) CreateCloudKeystore(ctx context.Context, request domain.CreateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	input, err := cloudKeystoreInputFromDomain(request)
	if err != nil {
		return nil, err
	}

	resp, err := CreateCloudKeystore(ctx, c.graphqlClient, input)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Keystore %s: %w", request.Name, err)
	}
	if resp == nil || resp.GetCreateCloudKeystore() == nil {
		return nil, fmt.Errorf("failed to create Cloud Keystore %s: empty response", request.Name)
	}

	ck := resp.GetCreateCloudKeystore().CloudKeystoreFields.toDomain()
	return &ck, nil
}

func (c *CloudProvidersClient) UpdateCloudKeystore(ctx context.Context, request domain.UpdateCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	if request.ID == "" {
		return nil, fmt.Errorf("cloud keystore ID cannot be empty")
	}

	// The API replaces the whole discovery configuration on every update, and
	// uses its defaults (no schedule, both flags false) for anything not sent.
	// Always send the current settings merged with the requested changes, so
	// that an update, even a rename, does not reset them.
	current, err := c.ListCloudKeystores(ctx, domain.GetCloudKeystoreRequest{CloudKeystoreID: &request.ID})
	if err != nil {
		return nil, fmt.Errorf("failed to read Cloud Keystore with ID %s before updating it: %w", request.ID, err)
	}
	if len(current) != 1 {
		return nil, fmt.Errorf("%w with ID %s", verror.CloudKeystoreNotFoundError, request.ID)
	}

	input := &CloudKeystoreUpdateInput{
		Id:                     request.ID,
		Name:                   request.Name,
		TeamId:                 request.TeamID,
		DiscoveryConfiguration: mergeDiscoveryConfiguration(current[0].DiscoveryConfiguration, request.Discovery),
	}

	resp, err := UpdateCloudKeystore(ctx, c.graphqlClient, input)
	if err != nil {
		return nil, fmt.Errorf("failed to update Cloud Keystore with ID %s: %w", request.ID, err)
	}
	if resp == nil || resp.GetUpdateCloudKeystore() == nil {
		return nil, fmt.Errorf("failed to update Cloud Keystore with ID %s: empty response", request.ID)
	}

	ck := resp.GetUpdateCloudKeystore().CloudKeystoreFields.toDomain()
	return &ck, nil
}

func (c *CloudProvidersClient) DeleteCloudKeystore(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("cloud keystore ID cannot be empty")
	}
	resp, err := DeleteCloudKeystores(ctx, c.graphqlClient, []string{id})
	if err != nil {
		return fmt.Errorf("failed to delete Cloud Keystore with ID %s: %w", id, err)
	}
	if resp == nil || !resp.GetDeleteCloudKeystore() {
		return fmt.Errorf("failed to delete Cloud Keystore with ID %s", id)
	}
	return nil
}

func (c *CloudProvidersClient) ListMachineIdentities(ctx context.Context, request domain.ListCloudMachineIdentitiesRequest) ([]domain.CloudMachineIdentity, error) {
	if request.KeystoreID == "" {
		return nil, fmt.Errorf("cloud keystore ID cannot be empty")
	}

	identities := make([]domain.CloudMachineIdentity, 0)
	var after *string
	for {
		resp, err := ListMachineIdentities(ctx, c.graphqlClient, &request.KeystoreID, after)
		if err != nil {
			return nil, fmt.Errorf("failed to list machine identities for Cloud Keystore with ID %s: %w", request.KeystoreID, err)
		}
		if resp == nil || resp.GetCloudMachineIdentities() == nil {
			return identities, nil
		}
		for _, node := range resp.GetCloudMachineIdentities().GetNodes() {
			mi, err := node.toDomain()
			if err != nil {
				return nil, err
			}
			identities = append(identities, *mi)
		}
		pageInfo := resp.GetCloudMachineIdentities().GetPageInfo()
		if pageInfo == nil || !pageInfo.GetHasNextPage() || pageInfo.GetEndCursor() == nil {
			return identities, nil
		}
		after = pageInfo.GetEndCursor()
	}
}

func (v *CloudProviderFields) toDomain() domain.CloudProvider {
	statusDetails := ""
	if v.StatusDetails != nil {
		statusDetails = *v.StatusDetails
	}
	cp := domain.CloudProvider{
		ID:             v.Id,
		Name:           v.Name,
		Type:           v.Type.toDomain(),
		Status:         v.Status.toDomain(),
		StatusDetails:  statusDetails,
		KeystoresCount: v.KeystoresCount,
	}

	switch cfg := v.Configuration.(type) {
	case *CloudProviderFieldsConfigurationCloudProviderAWSConfiguration:
		cp.AWS = &domain.CloudProviderAWSConfiguration{
			AccountID:  util.StringPointerToString(cfg.AccountId),
			Role:       util.StringPointerToString(cfg.Role),
			ExternalID: util.StringPointerToString(cfg.ExternalId),
		}
	case *CloudProviderFieldsConfigurationCloudProviderAzureConfiguration:
		cp.Azure = &domain.CloudProviderAzureConfiguration{
			ApplicationID: cfg.ApplicationId,
			DirectoryID:   cfg.DirectoryId,
		}
	case *CloudProviderFieldsConfigurationCloudProviderGCPConfiguration:
		cp.GCP = &domain.CloudProviderGCPConfiguration{
			ServiceAccountEmail:            cfg.ServiceAccountEmail,
			ProjectNumber:                  util.StringPointerToString(cfg.ProjectNumber),
			WorkloadIdentityPoolID:         util.StringPointerToString(cfg.WorkloadIdentityPoolId),
			WorkloadIdentityPoolProviderID: util.StringPointerToString(cfg.WorkloadIdentityPoolProviderId),
			AuthorizationMethod:            cfg.AuthorizationMethod.toDomain(),
			PublicKey:                      util.StringPointerToString(cfg.PublicKey),
			IssuerURL:                      util.StringPointerToString(cfg.IssuerUrl),
		}
	}
	return cp
}

func (v AuthorizationMethod) toDomain() domain.GCPAuthorizationMethod {
	switch v {
	case AuthorizationMethodVenafiGeneratedKey:
		return domain.GCPAuthorizationMethodVenafiGeneratedKey
	case AuthorizationMethodWorkloadIdentityFederation:
		return domain.GCPAuthorizationMethodWorkloadIdentityFederation
	default:
		return domain.GCPAuthorizationMethodUnknown
	}
}

func (v *CloudKeystoreFields) toDomain() domain.CloudKeystore {
	ck := domain.CloudKeystore{
		ID:                     v.Id,
		Name:                   v.Name,
		Type:                   v.Type.toDomain(),
		MachineIdentitiesCount: v.MachineIdentitiesCount,
	}

	if v.CloudProvider != nil {
		ck.CloudProviderID = v.CloudProvider.Id
		ck.CloudProviderName = v.CloudProvider.Name
	}

	switch cfg := v.Configuration.(type) {
	case *CloudKeystoreFieldsConfigurationCloudKeystoreACMConfiguration:
		accountID := ""
		if cfg.AccountId != nil {
			accountID = *cfg.AccountId
		}
		ck.ACM = &domain.CloudKeystoreACMConfiguration{Region: cfg.Region, AccountID: accountID}
	case *CloudKeystoreFieldsConfigurationCloudKeystoreAKVConfiguration:
		ck.AKV = &domain.CloudKeystoreAKVConfiguration{KeyVaultName: cfg.KeyVaultName}
	case *CloudKeystoreFieldsConfigurationCloudKeystoreGCMConfiguration:
		ck.GCM = &domain.CloudKeystoreGCMConfiguration{ProjectID: cfg.ProjectId, Location: cfg.Location}
	}

	if v.DiscoveryConfiguration != nil {
		schedule := ""
		if v.DiscoveryConfiguration.ScheduleSpecification != nil {
			schedule = *v.DiscoveryConfiguration.ScheduleSpecification
		}
		ck.DiscoveryConfiguration = &domain.CloudDiscoveryConfiguration{
			ScheduleSpecification:      schedule,
			IncludeExpiredCertificates: v.DiscoveryConfiguration.IncludeExpiredCertificates,
			IncludeRevokedCertificates: v.DiscoveryConfiguration.IncludeRevokedCertificates,
		}
	}

	return ck
}

func (v *ListMachineIdentitiesCloudMachineIdentitiesMachineIdentityConnectionNodesMachineIdentity) toDomain() (*domain.CloudMachineIdentity, error) {
	var metadata *domain.CertificateCloudMetadata
	if v.Metadata != nil {
		var err error
		metadata, err = cloudMetadataToDomain(*v.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cloud certificate metadata: %w", err)
		}
	}

	return &domain.CloudMachineIdentity{
		ID:                v.Id,
		CloudKeystoreID:   v.CloudKeystoreId,
		CloudKeystoreName: util.StringPointerToString(v.CloudKeystoreName),
		CloudProviderID:   util.StringPointerToString(v.CloudProviderId),
		CloudProviderName: util.StringPointerToString(v.CloudProviderName),
		CertificateID:     v.CertificateId,
		Metadata:          metadata,
		Status:            v.Status.toDomain(),
		StatusDetails:     util.StringPointerToString(v.StatusDetails),
	}, nil
}

func gcpAuthorizationMethodFromDomain(method domain.GCPAuthorizationMethod) *AuthorizationMethod {
	switch method {
	case domain.GCPAuthorizationMethodVenafiGeneratedKey:
		m := AuthorizationMethodVenafiGeneratedKey
		return &m
	case domain.GCPAuthorizationMethodWorkloadIdentityFederation:
		m := AuthorizationMethodWorkloadIdentityFederation
		return &m
	default:
		return nil
	}
}

func cloudKeystoreTypeFromDomain(keystoreType domain.CloudKeystoreType) *CloudKeystoreType {
	switch keystoreType {
	case domain.CloudKeystoreTypeACM:
		ckType := CloudKeystoreTypeAcm
		return &ckType
	case domain.CloudKeystoreTypeAKV:
		ckType := CloudKeystoreTypeAkv
		return &ckType
	case domain.CloudKeystoreTypeGCM:
		ckType := CloudKeystoreTypeGcm
		return &ckType
	default:
		return nil
	}
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func cloudProviderInputFromDomain(request domain.CreateCloudProviderRequest) (*CloudProviderInput, error) {
	if request.Name == "" {
		return nil, fmt.Errorf("cloud provider name cannot be empty")
	}
	providerType := cloudProviderTypeFromDomain(request.Type)
	if providerType == nil {
		return nil, fmt.Errorf("unsupported cloud provider type: %s", request.Type)
	}

	input := &CloudProviderInput{
		Name:   request.Name,
		Type:   *providerType,
		TeamId: optionalString(request.TeamID),
	}

	switch request.Type {
	case domain.CloudProviderTypeAWS:
		if request.AWS == nil {
			return nil, fmt.Errorf("AWS configuration is required for a cloud provider of type %s", request.Type)
		}
		input.AwsConfiguration = &CloudProviderAWSConfigurationInput{
			AccountId: request.AWS.AccountID,
			Role:      request.AWS.Role,
		}
	case domain.CloudProviderTypeAzure:
		if request.Azure == nil {
			return nil, fmt.Errorf("azure configuration is required for a cloud provider of type %s", request.Type)
		}
		input.AzureConfiguration = &CloudProviderAzureConfigurationInput{
			ApplicationId: request.Azure.ApplicationID,
			DirectoryId:   request.Azure.DirectoryID,
			Secret:        request.Azure.Secret,
		}
	case domain.CloudProviderTypeGCP:
		if request.GCP == nil {
			return nil, fmt.Errorf("GCP configuration is required for a cloud provider of type %s", request.Type)
		}
		input.GcpConfiguration = &CloudProviderGCPConfigurationInput{
			ServiceAccountEmail:            request.GCP.ServiceAccountEmail,
			ProjectNumber:                  optionalString(request.GCP.ProjectNumber),
			WorkloadIdentityPoolId:         optionalString(request.GCP.WorkloadIdentityPoolID),
			WorkloadIdentityPoolProviderId: optionalString(request.GCP.WorkloadIdentityPoolProviderID),
			AuthorizationMethod:            gcpAuthorizationMethodFromDomain(request.GCP.AuthorizationMethod),
		}
	}
	return input, nil
}

func cloudProviderUpdateInputFromDomain(request domain.UpdateCloudProviderRequest) (*CloudProviderUpdateInput, error) {
	if request.ID == "" {
		return nil, fmt.Errorf("cloud provider ID cannot be empty")
	}
	providerType := cloudProviderTypeFromDomain(request.Type)
	if providerType == nil {
		return nil, fmt.Errorf("unsupported cloud provider type: %s", request.Type)
	}

	input := &CloudProviderUpdateInput{
		Id:     request.ID,
		Type:   *providerType,
		Name:   request.Name,
		TeamId: request.TeamID,
	}

	if request.AWS != nil {
		if request.Type != domain.CloudProviderTypeAWS {
			return nil, fmt.Errorf("AWS configuration cannot be set on a cloud provider of type %s", request.Type)
		}
		input.AwsConfiguration = &CloudProviderAWSConfigurationUpdateInput{Role: request.AWS.Role}
	}
	if request.Azure != nil {
		if request.Type != domain.CloudProviderTypeAzure {
			return nil, fmt.Errorf("azure configuration cannot be set on a cloud provider of type %s", request.Type)
		}
		if request.Azure.Secret == "" {
			return nil, fmt.Errorf("azure secret is required when updating the azure configuration")
		}
		input.AzureConfiguration = &CloudProviderAzureConfigurationUpdateInput{
			ApplicationId: request.Azure.ApplicationID,
			DirectoryId:   request.Azure.DirectoryID,
			Secret:        request.Azure.Secret,
		}
	}
	if request.GCP != nil {
		if request.Type != domain.CloudProviderTypeGCP {
			return nil, fmt.Errorf("GCP configuration cannot be set on a cloud provider of type %s", request.Type)
		}
		input.GcpConfiguration = &CloudProviderGCPConfigurationUpdateInput{
			ProjectNumber:                  request.GCP.ProjectNumber,
			WorkloadIdentityPoolId:         request.GCP.WorkloadIdentityPoolID,
			WorkloadIdentityPoolProviderId: request.GCP.WorkloadIdentityPoolProviderID,
			AuthorizationMethod:            gcpAuthorizationMethodFromDomain(request.GCP.AuthorizationMethod),
		}
	}
	return input, nil
}

func cloudKeystoreInputFromDomain(request domain.CreateCloudKeystoreRequest) (*CloudKeystoreInput, error) {
	if request.Name == "" {
		return nil, fmt.Errorf("cloud keystore name cannot be empty")
	}
	if request.CloudProviderID == "" {
		return nil, fmt.Errorf("cloud provider ID cannot be empty")
	}
	keystoreType := cloudKeystoreTypeFromDomain(request.Type)
	if keystoreType == nil {
		return nil, fmt.Errorf("unsupported cloud keystore type: %s", request.Type)
	}

	input := &CloudKeystoreInput{
		Name:                   request.Name,
		Type:                   *keystoreType,
		CloudProviderId:        request.CloudProviderID,
		TeamId:                 optionalString(request.TeamID),
		DiscoveryConfiguration: discoveryConfigurationInputFromDomain(request.Discovery),
	}

	switch request.Type {
	case domain.CloudKeystoreTypeACM:
		if request.ACM == nil {
			return nil, fmt.Errorf("ACM configuration is required for a cloud keystore of type %s", request.Type)
		}
		input.AcmConfiguration = &CloudKeystoreACMConfigurationInput{
			Region:    request.ACM.Region,
			AccountId: optionalString(request.ACM.AccountID),
		}
	case domain.CloudKeystoreTypeAKV:
		if request.AKV == nil {
			return nil, fmt.Errorf("AKV configuration is required for a cloud keystore of type %s", request.Type)
		}
		input.AkvConfiguration = &CloudKeystoreAKVConfigurationInput{KeyVaultName: request.AKV.KeyVaultName}
	case domain.CloudKeystoreTypeGCM:
		if request.GCM == nil {
			return nil, fmt.Errorf("GCM configuration is required for a cloud keystore of type %s", request.Type)
		}
		input.GcmConfiguration = &CloudKeystoreGCMConfigurationInput{
			ProjectId: request.GCM.ProjectID,
			Location:  request.GCM.Location,
		}
	}
	return input, nil
}

func discoveryConfigurationInputFromDomain(options *domain.CloudDiscoveryOptions) *CloudDiscoveryConfigurationInput {
	if options == nil {
		return nil
	}
	return &CloudDiscoveryConfigurationInput{
		ScheduleSpecification:      scheduleSpecificationInput(options.ScheduleSpecification),
		IncludeExpiredCertificates: options.IncludeExpiredCertificates,
		IncludeRevokedCertificates: options.IncludeRevokedCertificates,
	}
}

// mergeDiscoveryConfiguration returns the complete discovery configuration
// that results from applying the given changes to the current one
func mergeDiscoveryConfiguration(current *domain.CloudDiscoveryConfiguration, changes *domain.CloudDiscoveryOptions) *CloudDiscoveryConfigurationInput {
	merged := domain.CloudDiscoveryConfiguration{}
	if current != nil {
		merged = *current
	}
	if changes != nil {
		if changes.ScheduleSpecification != nil {
			merged.ScheduleSpecification = *changes.ScheduleSpecification
		}
		if changes.IncludeExpiredCertificates != nil {
			merged.IncludeExpiredCertificates = *changes.IncludeExpiredCertificates
		}
		if changes.IncludeRevokedCertificates != nil {
			merged.IncludeRevokedCertificates = *changes.IncludeRevokedCertificates
		}
	}
	return &CloudDiscoveryConfigurationInput{
		ScheduleSpecification:      scheduleSpecificationInput(&merged.ScheduleSpecification),
		IncludeExpiredCertificates: &merged.IncludeExpiredCertificates,
		IncludeRevokedCertificates: &merged.IncludeRevokedCertificates,
	}
}

// scheduleSpecificationInput maps an empty schedule to nil: the API deletes the
// schedule when none is sent, whereas an empty string would be passed on to the
// scheduler as a crontab expression
func scheduleSpecificationInput(schedule *string) *string {
	if schedule == nil || *schedule == "" {
		return nil
	}
	return schedule
}
