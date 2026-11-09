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
	"sort"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/venafi"
)

// validateCloudManagementConnectionFlags checks the connection flags of the
// cloudprovider and cloudkeystore commands, which only NGTS supports
func validateCloudManagementConnectionFlags(commandName string) error {
	err := commonConnectionFlagsValidations(commandName)
	if err != nil {
		return err
	}

	if err := validateWorkspaceFlag(); err != nil {
		return err
	}

	// With --config the platform is only known once the file is loaded. It is
	// checked when connecting instead.
	if flags.config != "" {
		return nil
	}

	platform := flags.platform
	if platform == venafi.Undefined {
		platform = venafi.GetPlatformType(getPropertyFromEnvironment(vCertPlatform))
	}

	switch platform {
	case venafi.NGTS:
		return validateConnectionFlagsNGTS(commandName)
	case venafi.Undefined:
		return fmt.Errorf("command %s is only supported for %s. Set --platform %s", commandName, venafi.NGTS.String(), venafi.NGTS.String())
	default:
		return fmt.Errorf("command %s not supported for %s", commandName, platform.String())
	}
}

func validateOutputFormatFlag() error {
	switch strings.ToLower(flags.provisionFormat) {
	case "", "text", formatJson:
		return nil
	default:
		return fmt.Errorf("unexpected output format: %s. Accepted values: text, json", flags.provisionFormat)
	}
}

func validateCloudManagementFlags(commandName string) error {
	if err := validateCloudManagementConnectionFlags(commandName); err != nil {
		return err
	}
	return validateOutputFormatFlag()
}

func validateCloudProviderSelectorFlags() error {
	if flags.providerID == "" && flags.providerName == "" {
		return fmt.Errorf("please, provide either --%s or --%s", flagProviderID.Name, flagCloudProviderName.Name)
	}
	return nil
}

func validateCloudKeystoreSelectorFlags() error {
	if flags.keystoreID == "" && flags.keystoreName == "" {
		return fmt.Errorf("please, provide either --%s or --%s", flagCloudKeystoreID.Name, flagCloudKeystoreName.Name)
	}
	return nil
}

func validateCloudProviderCreateFlags(commandName string) error {
	if err := validateCloudManagementFlags(commandName); err != nil {
		return err
	}
	if flags.providerName == "" {
		return fmt.Errorf("missing cloud provider name. Set it using --%s", flagCloudProviderName.Name)
	}

	switch domain.GetCloudProviderType(flags.cloudType) {
	case domain.CloudProviderTypeAWS:
		return requireFlags(map[string]string{
			flagAWSAccountID.Name: flags.awsAccountID,
			flagAWSRole.Name:      flags.awsRole,
		})
	case domain.CloudProviderTypeAzure:
		return requireFlags(map[string]string{
			flagAzureApplicationID.Name: flags.azureApplicationID,
			flagAzureDirectoryID.Name:   flags.azureDirectoryID,
			flagAzureSecret.Name:        getAzureSecret(),
		})
	case domain.CloudProviderTypeGCP:
		if err := requireFlags(map[string]string{flagGCPServiceAccountEmail.Name: flags.gcpServiceAccountEmail}); err != nil {
			return err
		}
		return validateGCPAuthorizationMethodFlag()
	default:
		return fmt.Errorf("unexpected cloud provider type in --%s: %q. Accepted values: AWS, AZURE, GCP", flagCloudProviderType.Name, flags.cloudType)
	}
}

func validateCloudProviderListFlags(commandName string) error {
	if err := validateCloudManagementFlags(commandName); err != nil {
		return err
	}
	if flags.cloudType != "" && domain.GetCloudProviderType(flags.cloudType) == domain.CloudProviderTypeUnknown {
		return fmt.Errorf("unexpected cloud provider type in --%s: %q. Accepted values: AWS, AZURE, GCP", flagCloudProviderType.Name, flags.cloudType)
	}
	if flags.cloudStatus != "" && domain.GetCloudProviderStatus(flags.cloudStatus) == domain.CloudProviderStatusUnknown {
		return fmt.Errorf("unexpected cloud provider status in --%s: %q. Accepted values: VALIDATED, NOT_VALIDATED", flagCloudProviderStatus.Name, flags.cloudStatus)
	}
	return nil
}

func validateCloudProviderSelectFlags(commandName string) error {
	if err := validateCloudManagementFlags(commandName); err != nil {
		return err
	}
	return validateCloudProviderSelectorFlags()
}

func validateCloudProviderUpdateFlags(commandName string) error {
	if err := validateCloudProviderSelectFlags(commandName); err != nil {
		return err
	}
	if flags.awsAccountID != "" {
		return fmt.Errorf("the AWS account ID of a cloud provider cannot be changed")
	}
	if flags.gcpServiceAccountEmail != "" {
		return fmt.Errorf("the GCP service account email of a cloud provider cannot be changed")
	}
	if (flags.azureApplicationID != "" || flags.azureDirectoryID != "") && getAzureSecret() == "" {
		return fmt.Errorf("--%s is required when updating the Azure configuration", flagAzureSecret.Name)
	}
	return validateGCPAuthorizationMethodFlag()
}

func validateGCPAuthorizationMethodFlag() error {
	if flags.gcpAuthorizationMethod != "" && domain.GetGCPAuthorizationMethod(flags.gcpAuthorizationMethod) == domain.GCPAuthorizationMethodUnknown {
		return fmt.Errorf("unexpected GCP authorization method in --%s: %q. Accepted values: VENAFI_GENERATED_KEY, WORKLOAD_IDENTITY_FEDERATION",
			flagGCPAuthorizationMethod.Name, flags.gcpAuthorizationMethod)
	}
	return nil
}

func validateCloudKeystoreCreateFlags(commandName string) error {
	if err := validateCloudManagementFlags(commandName); err != nil {
		return err
	}
	if flags.keystoreName == "" {
		return fmt.Errorf("missing cloud keystore name. Set it using --%s", flagCloudKeystoreName.Name)
	}
	if err := validateCloudProviderSelectorFlags(); err != nil {
		return err
	}

	switch domain.GetCloudKeystoreType(flags.cloudType) {
	case domain.CloudKeystoreTypeACM:
		return requireFlags(map[string]string{flagAWSRegion.Name: flags.awsRegion})
	case domain.CloudKeystoreTypeAKV:
		return requireFlags(map[string]string{flagAzureKeyVaultName.Name: flags.azureKeyVaultName})
	case domain.CloudKeystoreTypeGCM:
		return requireFlags(map[string]string{
			flagGCPProjectID.Name: flags.gcpProjectID,
			flagGCPLocation.Name:  flags.gcpLocation,
		})
	default:
		return fmt.Errorf("unexpected cloud keystore type in --%s: %q. Accepted values: ACM, AKV, GCM", flagCloudKeystoreType.Name, flags.cloudType)
	}
}

func validateCloudKeystoreListFlags(commandName string) error {
	return validateCloudManagementFlags(commandName)
}

func validateCloudKeystoreSelectFlags(commandName string) error {
	if err := validateCloudManagementFlags(commandName); err != nil {
		return err
	}
	return validateCloudKeystoreSelectorFlags()
}

// requireFlags returns an error naming every flag in the map that has no value
func requireFlags(values map[string]string) error {
	missing := make([]string, 0)
	for name, value := range values {
		if value == "" {
			missing = append(missing, "--"+name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	// map iteration order is random, so sort for a stable message
	sort.Strings(missing)
	return fmt.Errorf("missing required flags for --%s %s: %s", flagCloudProviderType.Name, strings.ToUpper(flags.cloudType), strings.Join(missing, ", "))
}

// getAzureSecret returns the Azure secret from the flag or, failing that, the
// environment. The environment is read directly because env vars are not
// copied into the flags when --config is used.
func getAzureSecret() string {
	if flags.azureSecret != "" {
		return flags.azureSecret
	}
	return getPropertyFromEnvironment(vcertAzureSecret)
}
