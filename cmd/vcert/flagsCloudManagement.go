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
	"github.com/urfave/cli/v2"
)

// Flags for the cloudprovider and cloudkeystore commands. These commands are
// only supported by CyberArk Certificate Manager, SaaS (VCP) and Palo Alto
// Networks Next-Gen Trust Security (NGTS).
var (
	flagCloudPlatform = &cli.StringFlag{
		Name: "platform",
		Usage: "Use to specify the platform VCert will use to execute the given command. Accepted values: VCP, NGTS. " +
			"Required unless an API key is used, which means VCP.",
		Destination: &flags.platformString,
		Aliases:     []string{"p"},
	}

	flagProviderID = &cli.StringFlag{
		Name:        "provider-id",
		Usage:       "The ID of the cloud provider.",
		Destination: &flags.providerID,
	}

	flagCloudProviderName = &cli.StringFlag{
		Name:        "provider-name",
		Usage:       "The name of the cloud provider.",
		Destination: &flags.providerName,
	}

	flagCloudProviderType = &cli.StringFlag{
		Name:        "type",
		Usage:       "The type of the cloud provider. Accepted values: AWS, AZURE, GCP",
		Destination: &flags.cloudType,
	}

	flagCloudProviderStatus = &cli.StringFlag{
		Name:        "status",
		Usage:       "Only list cloud providers with this validation status. Accepted values: VALIDATED, NOT_VALIDATED",
		Destination: &flags.cloudStatus,
	}

	flagCloudKeystoreID = &cli.StringFlag{
		Name:        "keystore-id",
		Usage:       "The ID of the cloud keystore.",
		Destination: &flags.keystoreID,
	}

	flagCloudKeystoreName = &cli.StringFlag{
		Name:        "keystore-name",
		Usage:       "The name of the cloud keystore.",
		Destination: &flags.keystoreName,
	}

	flagCloudKeystoreType = &cli.StringFlag{
		Name: "type",
		Usage: "The type of the cloud keystore. Accepted values: ACM (AWS Certificate Manager), AKV (Azure Key Vault), " +
			"GCM (Google Cloud Certificate Manager)",
		Destination: &flags.cloudType,
	}

	flagNewName = &cli.StringFlag{
		Name:        "new-name",
		Usage:       "The new name to give to the resource.",
		Destination: &flags.newName,
	}

	flagTeamID = &cli.StringFlag{
		Name:        "team",
		Aliases:     []string{"team-id"},
		Usage:       "The name or ID of the team that owns the resource. Required for VCP when creating; NGTS only accepts an ID.",
		Destination: &flags.teamID,
	}

	flagAWSAccountID = &cli.StringFlag{
		Name:        "aws-account-id",
		Usage:       "The AWS account ID. Required for AWS cloud providers; optional for ACM keystores.",
		Destination: &flags.awsAccountID,
	}

	flagAWSRole = &cli.StringFlag{
		Name:        "aws-role",
		Usage:       "The name of the AWS IAM role the platform assumes. Required for AWS cloud providers.",
		Destination: &flags.awsRole,
	}

	flagAWSRegion = &cli.StringFlag{
		Name:        "aws-region",
		Usage:       "The AWS region of the certificate manager. Required for ACM keystores.",
		Destination: &flags.awsRegion,
	}

	flagAzureApplicationID = &cli.StringFlag{
		Name:        "azure-application-id",
		Usage:       "The Azure application (client) ID. Required for Azure cloud providers.",
		Destination: &flags.azureApplicationID,
	}

	flagAzureDirectoryID = &cli.StringFlag{
		Name:        "azure-directory-id",
		Usage:       "The Azure directory (tenant) ID. Required for Azure cloud providers.",
		Destination: &flags.azureDirectoryID,
	}

	flagAzureSecret = &cli.StringFlag{
		Name: "azure-secret",
		Usage: "The Azure application client secret. Required for Azure cloud providers. " +
			"Can also be set with the " + vcertAzureSecret + " environment variable to keep it out of the shell history.",
		Destination: &flags.azureSecret,
	}

	flagAzureKeyVaultName = &cli.StringFlag{
		Name:        "azure-key-vault-name",
		Usage:       "The name of the Azure key vault. Required for AKV keystores.",
		Destination: &flags.azureKeyVaultName,
	}

	flagGCPServiceAccountEmail = &cli.StringFlag{
		Name:        "gcp-service-account-email",
		Usage:       "The email of the GCP service account. Required for GCP cloud providers.",
		Destination: &flags.gcpServiceAccountEmail,
	}

	flagGCPProjectNumber = &cli.StringFlag{
		Name:        "gcp-project-number",
		Usage:       "The GCP project number. Used with workload identity federation.",
		Destination: &flags.gcpProjectNumber,
	}

	flagGCPWorkloadIdentityPoolID = &cli.StringFlag{
		Name:        "gcp-workload-identity-pool-id",
		Usage:       "The GCP workload identity pool ID. Used with workload identity federation.",
		Destination: &flags.gcpWorkloadIdentityPoolID,
	}

	flagGCPWorkloadIdentityPoolProviderID = &cli.StringFlag{
		Name:        "gcp-workload-identity-pool-provider-id",
		Usage:       "The GCP workload identity pool provider ID. Used with workload identity federation.",
		Destination: &flags.gcpWorkloadIdentityPoolProviderID,
	}

	flagGCPAuthorizationMethod = &cli.StringFlag{
		Name:        "gcp-authorization-method",
		Usage:       "How the platform authenticates to GCP. Accepted values: VENAFI_GENERATED_KEY, WORKLOAD_IDENTITY_FEDERATION",
		Destination: &flags.gcpAuthorizationMethod,
	}

	flagGCPProjectID = &cli.StringFlag{
		Name:        "gcp-project-id",
		Usage:       "The GCP project ID. Required for GCM keystores.",
		Destination: &flags.gcpProjectID,
	}

	flagGCPLocation = &cli.StringFlag{
		Name:        "gcp-location",
		Usage:       "The GCP location of the certificate manager, for example \"global\". Required for GCM keystores.",
		Destination: &flags.gcpLocation,
	}

	flagDiscoverySchedule = &cli.StringFlag{
		Name:        "discovery-schedule",
		Usage:       "A crontab expression for scheduled discovery, for example \"00 03 * * *\" runs every day at 3 AM.",
		Destination: &flags.discoverySchedule,
	}

	flagIncludeExpired = &cli.BoolFlag{
		Name:        "include-expired",
		Usage:       "Whether discovery includes expired certificates. Use --include-expired=false to turn it off.",
		Destination: &flags.includeExpired,
	}

	flagIncludeRevoked = &cli.BoolFlag{
		Name:        "include-revoked",
		Usage:       "Whether discovery includes revoked certificates. Use --include-revoked=false to turn it off.",
		Destination: &flags.includeRevoked,
	}

	flagDiscoveryWait = &cli.BoolFlag{
		Name:        "wait",
		Usage:       "Wait for the discovery to finish and print its results.",
		Destination: &flags.discoveryWait,
	}

	flagDiscoveryTimeout = &cli.IntFlag{
		Name:        "timeout",
		Value:       600,
		Usage:       "Seconds to wait for the discovery to finish when --wait is set.",
		Destination: &flags.discoveryTimeout,
	}

	flagNewlyDiscovered = &cli.BoolFlag{
		Name:        "newly-discovered",
		Usage:       "Only list machine identities found by the latest discovery.",
		Destination: &flags.newlyDiscovered,
	}

	cloudManagementCommonFlags = flagsApppend(
		flagKey,
		flagToken,
		flagUrl,
		flagCloudPlatform,
		flagWorkspace,
		flagConfig,
		flagProfile,
		flagTrustBundle,
		flagProvisionFormat,
		flagProvisionOutputFile,
		flagVerbose,
	)

	cloudProviderConfigFlags = []cli.Flag{
		flagAWSAccountID,
		flagAWSRole,
		flagAzureApplicationID,
		flagAzureDirectoryID,
		flagAzureSecret,
		flagGCPServiceAccountEmail,
		flagGCPProjectNumber,
		flagGCPWorkloadIdentityPoolID,
		flagGCPWorkloadIdentityPoolProviderID,
		flagGCPAuthorizationMethod,
	}

	cloudProviderSelectorFlags = []cli.Flag{flagProviderID, flagCloudProviderName}

	cloudKeystoreSelectorFlags = []cli.Flag{flagCloudKeystoreID, flagCloudKeystoreName, flagProviderID, flagCloudProviderName}

	cloudDiscoveryConfigFlags = []cli.Flag{flagDiscoverySchedule, flagIncludeExpired, flagIncludeRevoked}

	cloudProviderCreateFlags = flagsApppend(cloudManagementCommonFlags, flagCloudProviderName, flagCloudProviderType, flagTeamID, cloudProviderConfigFlags)
	cloudProviderGetFlags    = flagsApppend(cloudManagementCommonFlags, cloudProviderSelectorFlags)
	cloudProviderListFlags   = flagsApppend(cloudManagementCommonFlags, flagCloudProviderName, flagCloudProviderType, flagCloudProviderStatus)
	cloudProviderUpdateFlags = flagsApppend(cloudManagementCommonFlags, cloudProviderSelectorFlags, flagNewName, flagTeamID, cloudProviderConfigFlags)

	cloudKeystoreCreateFlags = flagsApppend(cloudManagementCommonFlags, flagCloudKeystoreName, flagCloudKeystoreType,
		flagProviderID, flagCloudProviderName, flagTeamID, flagAWSRegion, flagAWSAccountID, flagAzureKeyVaultName,
		flagGCPProjectID, flagGCPLocation, cloudDiscoveryConfigFlags)
	cloudKeystoreGetFlags               = flagsApppend(cloudManagementCommonFlags, cloudKeystoreSelectorFlags)
	cloudKeystoreListFlags              = flagsApppend(cloudManagementCommonFlags, flagProviderID, flagCloudProviderName)
	cloudKeystoreUpdateFlags            = flagsApppend(cloudManagementCommonFlags, cloudKeystoreSelectorFlags, flagNewName, flagTeamID, cloudDiscoveryConfigFlags)
	cloudKeystoreDiscoverFlags          = flagsApppend(cloudManagementCommonFlags, cloudKeystoreSelectorFlags, flagDiscoveryWait, flagDiscoveryTimeout)
	cloudKeystoreMachineIdentitiesFlags = flagsApppend(cloudManagementCommonFlags, cloudKeystoreSelectorFlags, flagNewlyDiscovered)
)
