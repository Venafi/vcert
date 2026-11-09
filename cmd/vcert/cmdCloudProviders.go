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

package main

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5/pkg/domain"
)

var (
	cloudProviderCommands = stringSlice{
		subCommandCreateName,
		subCommandGetName,
		subCommandListName,
		subCommandUpdateName,
		subCommandDeleteName,
		subCommandValidateName,
	}

	commandCloudProvider = &cli.Command{
		Name:  commandCloudProviderName,
		Usage: "To manage cloud providers in Palo Alto Networks Next-Gen Trust Security (NGTS)",
		Action: func(c *cli.Context) error {
			return fmt.Errorf("the following subcommand(s) are required: \n%s", createBulletList(cloudProviderCommands))
		},
		Subcommands: []*cli.Command{
			{
				Name:   subCommandCreateName,
				Usage:  "Create a cloud provider",
				Before: runBeforeCloudManagementCommand,
				Flags:  cloudProviderCreateFlags,
				UsageText: `vcert cloudprovider create -p ngts -t <access token> --provider-name <name> --type <AWS|AZURE|GCP> <type specific options>

   vcert cloudprovider create -p ngts -t <access token> --provider-name "My AWS" --type AWS --aws-account-id 123456789012 --aws-role my-venafi-role
   VCERT_AZURE_SECRET=<secret> vcert cloudprovider create -p ngts -t <access token> --provider-name "My Azure" --type AZURE --azure-application-id <id> --azure-directory-id <id>
   vcert cloudprovider create -p ngts -t <access token> --provider-name "My GCP" --type GCP --gcp-service-account-email sa@project.iam.gserviceaccount.com --gcp-authorization-method VENAFI_GENERATED_KEY`,
				Action: doCommandCloudProviderCreate,
			},
			{
				Name:      subCommandGetName,
				Usage:     "Show a cloud provider",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudProviderGetFlags,
				UsageText: `vcert cloudprovider get -p ngts -t <access token> (--provider-id <id> | --provider-name <name>) [--format json]`,
				Action:    doCommandCloudProviderGet,
			},
			{
				Name:      subCommandListName,
				Usage:     "List cloud providers",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudProviderListFlags,
				UsageText: `vcert cloudprovider list -p ngts -t <access token> [--type <AWS|AZURE|GCP>] [--status <VALIDATED|NOT_VALIDATED>] [--provider-name <name>] [--format json]`,
				Action:    doCommandCloudProviderList,
			},
			{
				Name:   subCommandUpdateName,
				Usage:  "Update a cloud provider. Only the given options are changed",
				Before: runBeforeCloudManagementCommand,
				Flags:  cloudProviderUpdateFlags,
				UsageText: `vcert cloudprovider update -p ngts -t <access token> (--provider-id <id> | --provider-name <name>) <options to change>

   vcert cloudprovider update -p ngts -t <access token> --provider-name "My AWS" --new-name "Production AWS" --aws-role new-role`,
				Action: doCommandCloudProviderUpdate,
			},
			{
				Name:      subCommandDeleteName,
				Usage:     "Delete a cloud provider",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudProviderGetFlags,
				UsageText: `vcert cloudprovider delete -p ngts -t <access token> (--provider-id <id> | --provider-name <name>)`,
				Action:    doCommandCloudProviderDelete,
			},
			{
				Name:      subCommandValidateName,
				Usage:     "Check that NGTS can access the cloud provider with its configured credentials",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudProviderGetFlags,
				UsageText: `vcert cloudprovider validate -p ngts -t <access token> (--provider-id <id> | --provider-name <name>)`,
				Action:    doCommandCloudProviderValidate,
			},
		},
	}
)

func doCommandCloudProviderCreate(c *cli.Context) error {
	if err := validateCloudProviderCreateFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudProviderManager(c)
	if err != nil {
		return err
	}

	request := domain.CreateCloudProviderRequest{
		Name:   flags.providerName,
		Type:   domain.GetCloudProviderType(flags.cloudType),
		TeamID: flags.teamID,
	}
	switch request.Type {
	case domain.CloudProviderTypeAWS:
		request.AWS = &domain.CloudProviderAWSConfiguration{
			AccountID: flags.awsAccountID,
			Role:      flags.awsRole,
		}
	case domain.CloudProviderTypeAzure:
		request.Azure = &domain.CloudProviderAzureConfiguration{
			ApplicationID: flags.azureApplicationID,
			DirectoryID:   flags.azureDirectoryID,
			Secret:        getAzureSecret(),
		}
	case domain.CloudProviderTypeGCP:
		request.GCP = &domain.CloudProviderGCPConfiguration{
			ServiceAccountEmail:            flags.gcpServiceAccountEmail,
			ProjectNumber:                  flags.gcpProjectNumber,
			WorkloadIdentityPoolID:         flags.gcpWorkloadIdentityPoolID,
			WorkloadIdentityPoolProviderID: flags.gcpWorkloadIdentityPoolProviderID,
			AuthorizationMethod:            domain.GetGCPAuthorizationMethod(flags.gcpAuthorizationMethod),
		}
	}

	provider, err := manager.CreateCloudProvider(request)
	if err != nil {
		return err
	}
	return writeCloudManagementResult(newCloudProviderOutput(*provider))
}

func doCommandCloudProviderGet(c *cli.Context) error {
	if err := validateCloudProviderSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudProviderManager(c)
	if err != nil {
		return err
	}
	provider, err := resolveCloudProvider(manager, flags.providerID, flags.providerName)
	if err != nil {
		return err
	}
	return writeCloudManagementResult(newCloudProviderOutput(*provider))
}

func doCommandCloudProviderList(c *cli.Context) error {
	if err := validateCloudProviderListFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudProviderManager(c)
	if err != nil {
		return err
	}
	providers, err := manager.ListCloudProviders(domain.GetCloudProviderRequest{
		Name:   flags.providerName,
		Type:   domain.GetCloudProviderType(flags.cloudType),
		Status: domain.GetCloudProviderStatus(flags.cloudStatus),
	})
	if err != nil {
		return err
	}

	result := make(cloudProviderListOutput, 0, len(providers))
	for _, p := range providers {
		result = append(result, newCloudProviderOutput(p))
	}
	return writeCloudManagementResult(result)
}

func doCommandCloudProviderUpdate(c *cli.Context) error {
	if err := validateCloudProviderUpdateFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudProviderManager(c)
	if err != nil {
		return err
	}
	// The update API needs the provider type, so look the provider up first
	provider, err := resolveCloudProvider(manager, flags.providerID, flags.providerName)
	if err != nil {
		return err
	}

	request, err := buildUpdateCloudProviderRequest(c, *provider)
	if err != nil {
		return err
	}

	updated, err := manager.UpdateCloudProvider(request)
	if err != nil {
		return err
	}
	return writeCloudManagementResult(newCloudProviderOutput(*updated))
}

func buildUpdateCloudProviderRequest(c *cli.Context, provider domain.CloudProvider) (domain.UpdateCloudProviderRequest, error) {
	request := domain.UpdateCloudProviderRequest{
		ID:     provider.ID,
		Type:   provider.Type,
		Name:   optionalFlag(flags.newName),
		TeamID: optionalFlag(flags.teamID),
	}

	awsChanged := flags.awsRole != ""
	// Only an explicit --azure-secret counts as a change: VCERT_AZURE_SECRET may
	// be exported in the environment while updating a provider of another type
	azureChanged := flags.azureApplicationID != "" || flags.azureDirectoryID != "" || c.IsSet(flagAzureSecret.Name)
	gcpChanged := flags.gcpProjectNumber != "" || flags.gcpWorkloadIdentityPoolID != "" ||
		flags.gcpWorkloadIdentityPoolProviderID != "" || flags.gcpAuthorizationMethod != ""

	for typ, changed := range map[domain.CloudProviderType]bool{
		domain.CloudProviderTypeAWS:   awsChanged,
		domain.CloudProviderTypeAzure: azureChanged,
		domain.CloudProviderTypeGCP:   gcpChanged,
	} {
		if changed && typ != provider.Type {
			return request, fmt.Errorf("cloud provider %q is of type %s, so its %s options cannot be set", provider.Name, provider.Type, typ)
		}
	}

	switch {
	case awsChanged:
		request.AWS = &domain.CloudProviderAWSConfigurationUpdate{Role: optionalFlag(flags.awsRole)}
	case azureChanged:
		secret := getAzureSecret()
		if secret == "" {
			return request, fmt.Errorf("--%s is required when updating the Azure configuration", flagAzureSecret.Name)
		}
		request.Azure = &domain.CloudProviderAzureConfigurationUpdate{
			ApplicationID: optionalFlag(flags.azureApplicationID),
			DirectoryID:   optionalFlag(flags.azureDirectoryID),
			Secret:        secret,
		}
	case gcpChanged:
		request.GCP = &domain.CloudProviderGCPConfigurationUpdate{
			ProjectNumber:                  optionalFlag(flags.gcpProjectNumber),
			WorkloadIdentityPoolID:         optionalFlag(flags.gcpWorkloadIdentityPoolID),
			WorkloadIdentityPoolProviderID: optionalFlag(flags.gcpWorkloadIdentityPoolProviderID),
			AuthorizationMethod:            domain.GetGCPAuthorizationMethod(flags.gcpAuthorizationMethod),
		}
	}

	if request.Name == nil && request.TeamID == nil && request.AWS == nil && request.Azure == nil && request.GCP == nil {
		return request, fmt.Errorf("nothing to update. Provide at least one option to change")
	}
	return request, nil
}

func doCommandCloudProviderDelete(c *cli.Context) error {
	if err := validateCloudProviderSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudProviderManager(c)
	if err != nil {
		return err
	}
	provider, err := resolveCloudProvider(manager, flags.providerID, flags.providerName)
	if err != nil {
		return err
	}
	if err := manager.DeleteCloudProvider(provider.ID); err != nil {
		return err
	}
	return writeCloudManagementResult(deletedOutput{ID: provider.ID, Name: provider.Name, Deleted: true})
}

func doCommandCloudProviderValidate(c *cli.Context) error {
	if err := validateCloudProviderSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudProviderManager(c)
	if err != nil {
		return err
	}
	provider, err := resolveCloudProvider(manager, flags.providerID, flags.providerName)
	if err != nil {
		return err
	}
	result, err := manager.ValidateCloudProvider(provider.ID)
	if err != nil {
		return err
	}

	err = writeCloudManagementResult(cloudProviderValidationOutput{
		ID:      provider.ID,
		Name:    provider.Name,
		Status:  result.Status.String(),
		Details: result.Details,
	})
	if err != nil {
		return err
	}
	if result.Status != domain.CloudProviderStatusValidated {
		return fmt.Errorf("cloud provider %q failed validation", provider.Name)
	}
	return nil
}
