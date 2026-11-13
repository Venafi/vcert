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
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

var (
	cloudKeystoreCommands = stringSlice{
		subCommandCreateName,
		subCommandGetName,
		subCommandListName,
		subCommandUpdateName,
		subCommandDeleteName,
		subCommandMachineIdentitiesName,
	}

	commandCloudKeystore = &cli.Command{
		Name:  commandCloudKeystoreName,
		Usage: "To manage cloud keystores, including their discovery settings, in CyberArk Certificate Manager, SaaS (VCP) or Palo Alto Networks Next-Gen Trust Security (NGTS)",
		Action: func(c *cli.Context) error {
			return fmt.Errorf("the following subcommand(s) are required: \n%s", createBulletList(cloudKeystoreCommands))
		},
		Subcommands: []*cli.Command{
			{
				Name:   subCommandCreateName,
				Usage:  "Create a cloud keystore",
				Before: runBeforeCloudManagementCommand,
				Flags:  cloudKeystoreCreateFlags,
				UsageText: `vcert cloudkeystore create -p <vcp|ngts> (-k <API key> | -t <access token>) --keystore-name <name> --type <ACM|AKV|GCM> (--provider-id <id> | --provider-name <name>) <type specific options>

   vcert cloudkeystore create -p vcp -k <API key> --team "Cloud Admins" --keystore-name "us-east-1" --type ACM --provider-name "My AWS" --aws-region us-east-1
   vcert cloudkeystore create -p ngts -t <access token> --keystore-name "us-east-1" --type ACM --provider-name "My AWS" --aws-region us-east-1
   vcert cloudkeystore create -p ngts -t <access token> --keystore-name "prod vault" --type AKV --provider-name "My Azure" --azure-key-vault-name prod-vault
   vcert cloudkeystore create -p ngts -t <access token> --keystore-name "global" --type GCM --provider-name "My GCP" --gcp-project-id my-project --gcp-location global --discovery-schedule "00 03 * * *"`,
				Action: doCommandCloudKeystoreCreate,
			},
			{
				Name:      subCommandGetName,
				Usage:     "Show a cloud keystore",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudKeystoreGetFlags,
				UsageText: `vcert cloudkeystore get -p <vcp|ngts> (-k <API key> | -t <access token>) (--keystore-id <id> | --keystore-name <name> [--provider-name <name>]) [--format json]`,
				Action:    doCommandCloudKeystoreGet,
			},
			{
				Name:      subCommandListName,
				Usage:     "List cloud keystores",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudKeystoreListFlags,
				UsageText: `vcert cloudkeystore list -p <vcp|ngts> (-k <API key> | -t <access token>) [--provider-id <id> | --provider-name <name>] [--format json]`,
				Action:    doCommandCloudKeystoreList,
			},
			{
				Name:   subCommandUpdateName,
				Usage:  "Update a cloud keystore. Only the given options are changed",
				Before: runBeforeCloudManagementCommand,
				Flags:  cloudKeystoreUpdateFlags,
				UsageText: `vcert cloudkeystore update -p <vcp|ngts> (-k <API key> | -t <access token>) (--keystore-id <id> | --keystore-name <name>) <options to change>

   vcert cloudkeystore update -p ngts -t <access token> --keystore-id <id> --discovery-schedule "00 03 * * *" --include-expired=false`,
				Action: doCommandCloudKeystoreUpdate,
			},
			{
				Name:      subCommandDeleteName,
				Usage:     "Delete a cloud keystore",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudKeystoreGetFlags,
				UsageText: `vcert cloudkeystore delete -p <vcp|ngts> (-k <API key> | -t <access token>) (--keystore-id <id> | --keystore-name <name> [--provider-name <name>])`,
				Action:    doCommandCloudKeystoreDelete,
			},
			{
				Name:      subCommandMachineIdentitiesName,
				Usage:     "List the certificates installed in a cloud keystore, or found in it by the platform",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudKeystoreMachineIdentitiesFlags,
				UsageText: `vcert cloudkeystore machine-identities -p <vcp|ngts> (-k <API key> | -t <access token>) (--keystore-id <id> | --keystore-name <name>) [--format json]`,
				Action:    doCommandCloudKeystoreMachineIdentities,
			},
		},
	}
)

func doCommandCloudKeystoreCreate(c *cli.Context) error {
	if err := validateCloudKeystoreCreateFlags(cloudCommandName(c)); err != nil {
		return err
	}
	connector, err := connectForCloudManagement(c)
	if err != nil {
		return err
	}
	keystoreManager, ok := connector.(endpoint.CloudKeystoreManager)
	if !ok {
		return fmt.Errorf("command %s not supported for %s", cloudCommandName(c), connector.GetType())
	}
	providerManager, ok := connector.(endpoint.CloudProviderManager)
	if !ok {
		return fmt.Errorf("command %s not supported for %s", cloudCommandName(c), connector.GetType())
	}

	providerID := flags.providerID
	if providerID == "" {
		provider, err := resolveCloudProvider(providerManager, "", flags.providerName)
		if err != nil {
			return err
		}
		providerID = provider.ID
	}

	request := domain.CreateCloudKeystoreRequest{
		Name:            flags.keystoreName,
		Type:            domain.GetCloudKeystoreType(flags.cloudType),
		CloudProviderID: providerID,
		TeamID:          flags.teamID,
		Discovery:       discoveryOptionsFromFlags(c),
	}
	switch request.Type {
	case domain.CloudKeystoreTypeACM:
		request.ACM = &domain.CloudKeystoreACMConfiguration{Region: flags.awsRegion, AccountID: flags.awsAccountID}
	case domain.CloudKeystoreTypeAKV:
		request.AKV = &domain.CloudKeystoreAKVConfiguration{KeyVaultName: flags.azureKeyVaultName}
	case domain.CloudKeystoreTypeGCM:
		request.GCM = &domain.CloudKeystoreGCMConfiguration{ProjectID: flags.gcpProjectID, Location: flags.gcpLocation}
	}

	keystore, err := keystoreManager.CreateCloudKeystore(request)
	if err != nil {
		return err
	}
	return writeCloudManagementResult(newCloudKeystoreOutput(*keystore))
}

func doCommandCloudKeystoreGet(c *cli.Context) error {
	if err := validateCloudKeystoreSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudKeystoreManager(c)
	if err != nil {
		return err
	}
	keystore, err := resolveCloudKeystore(manager)
	if err != nil {
		return err
	}
	return writeCloudManagementResult(newCloudKeystoreOutput(*keystore))
}

func doCommandCloudKeystoreList(c *cli.Context) error {
	if err := validateCloudKeystoreListFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudKeystoreManager(c)
	if err != nil {
		return err
	}
	keystores, err := manager.ListCloudKeystores(domain.GetCloudKeystoreRequest{
		CloudProviderID:   optionalFlag(flags.providerID),
		CloudProviderName: optionalFlag(flags.providerName),
	})
	if err != nil {
		return err
	}

	result := make(cloudKeystoreListOutput, 0, len(keystores))
	for _, k := range keystores {
		result = append(result, newCloudKeystoreOutput(k))
	}
	return writeCloudManagementResult(result)
}

func doCommandCloudKeystoreUpdate(c *cli.Context) error {
	if err := validateCloudKeystoreSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	request := domain.UpdateCloudKeystoreRequest{
		Name:      optionalFlag(flags.newName),
		TeamID:    optionalFlag(flags.teamID),
		Discovery: discoveryOptionsFromFlags(c),
	}
	if request.Name == nil && request.TeamID == nil && request.Discovery == nil {
		return fmt.Errorf("nothing to update. Provide at least one option to change")
	}

	manager, err := getCloudKeystoreManager(c)
	if err != nil {
		return err
	}
	keystore, err := resolveCloudKeystore(manager)
	if err != nil {
		return err
	}
	request.ID = keystore.ID

	updated, err := manager.UpdateCloudKeystore(request)
	if err != nil {
		return err
	}
	return writeCloudManagementResult(newCloudKeystoreOutput(*updated))
}

func doCommandCloudKeystoreDelete(c *cli.Context) error {
	if err := validateCloudKeystoreSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudKeystoreManager(c)
	if err != nil {
		return err
	}
	keystore, err := resolveCloudKeystore(manager)
	if err != nil {
		return err
	}
	if err := manager.DeleteCloudKeystore(keystore.ID); err != nil {
		return err
	}
	return writeCloudManagementResult(deletedOutput{ID: keystore.ID, Name: keystore.Name, Deleted: true})
}

func doCommandCloudKeystoreMachineIdentities(c *cli.Context) error {
	if err := validateCloudKeystoreSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	manager, err := getCloudKeystoreManager(c)
	if err != nil {
		return err
	}
	keystore, err := resolveCloudKeystore(manager)
	if err != nil {
		return err
	}

	identities, err := manager.ListMachineIdentities(domain.ListCloudMachineIdentitiesRequest{KeystoreID: keystore.ID})
	if err != nil {
		return err
	}

	result := make(machineIdentityListOutput, 0, len(identities))
	for _, mi := range identities {
		result = append(result, newMachineIdentityOutput(mi))
	}
	return writeCloudManagementResult(result)
}
