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
	"time"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

// discoveryPollInterval is how often `cloudkeystore discover --wait` checks
// the discovery status. It is a variable so that tests can shorten it.
var discoveryPollInterval = 10 * time.Second

var (
	cloudKeystoreCommands = stringSlice{
		subCommandCreateName,
		subCommandGetName,
		subCommandListName,
		subCommandUpdateName,
		subCommandDeleteName,
		subCommandDiscoverName,
		subCommandAbortDiscoveryName,
		subCommandMachineIdentitiesName,
	}

	commandCloudKeystore = &cli.Command{
		Name:  commandCloudKeystoreName,
		Usage: "To manage cloud keystores and run certificate discovery in CyberArk Certificate Manager, SaaS (VCP) or Palo Alto Networks Next-Gen Trust Security (NGTS)",
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
				Usage:     "Show a cloud keystore, including the status of its latest discovery",
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
				Name:   subCommandDiscoverName,
				Usage:  "Start a certificate discovery on a cloud keystore",
				Before: runBeforeCloudManagementCommand,
				Flags:  cloudKeystoreDiscoverFlags,
				UsageText: `vcert cloudkeystore discover -p <vcp|ngts> (-k <API key> | -t <access token>) (--keystore-id <id> | --keystore-name <name>) [--wait [--timeout <seconds>]]

   Without --wait the command returns once the discovery has started; follow it with "vcert cloudkeystore get".`,
				Action: doCommandCloudKeystoreDiscover,
			},
			{
				Name:      subCommandAbortDiscoveryName,
				Usage:     "Abort the running certificate discovery on a cloud keystore",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudKeystoreGetFlags,
				UsageText: `vcert cloudkeystore abort-discovery -p <vcp|ngts> (-k <API key> | -t <access token>) (--keystore-id <id> | --keystore-name <name>)`,
				Action:    doCommandCloudKeystoreAbortDiscovery,
			},
			{
				Name:      subCommandMachineIdentitiesName,
				Usage:     "List the certificates installed in or discovered on a cloud keystore",
				Before:    runBeforeCloudManagementCommand,
				Flags:     cloudKeystoreMachineIdentitiesFlags,
				UsageText: `vcert cloudkeystore machine-identities -p <vcp|ngts> (-k <API key> | -t <access token>) (--keystore-id <id> | --keystore-name <name>) [--newly-discovered] [--format json]`,
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

func doCommandCloudKeystoreDiscover(c *cli.Context) error {
	if err := validateCloudKeystoreSelectFlags(cloudCommandName(c)); err != nil {
		return err
	}
	if flags.discoveryWait && flags.discoveryTimeout <= 0 {
		return fmt.Errorf("--%s must be greater than 0", flagDiscoveryTimeout.Name)
	}
	manager, err := getCloudKeystoreManager(c)
	if err != nil {
		return err
	}
	keystore, err := resolveCloudKeystore(manager)
	if err != nil {
		return err
	}

	workflow, err := manager.StartCloudDiscovery(keystore.ID)
	if err != nil {
		return err
	}
	if !flags.discoveryWait {
		return writeCloudManagementResult(discoveryStartedOutput{
			KeystoreID:   keystore.ID,
			KeystoreName: keystore.Name,
			WorkflowID:   workflow.WorkflowID,
			WorkflowName: workflow.WorkflowName,
		})
	}

	timeout := time.Duration(flags.discoveryTimeout) * time.Second
	finished, err := waitForCloudDiscovery(manager, keystore.ID, keystore.Discovery, timeout)
	if err != nil {
		return err
	}
	if err := writeCloudManagementResult(newCloudKeystoreOutput(*finished)); err != nil {
		return err
	}
	if finished.Discovery.Status != domain.CloudDiscoveryStatusCompleted {
		return fmt.Errorf("discovery on cloud keystore %q finished with status %s", keystore.Name, finished.Discovery.Status)
	}
	return nil
}

// waitForCloudDiscovery polls the keystore until the discovery started after
// previous has finished. previous is the keystore's discovery before the new
// one was started, so that a finished earlier run is not mistaken for the new one.
func waitForCloudDiscovery(manager endpoint.CloudKeystoreManager, keystoreID string, previous *domain.CloudDiscovery, timeout time.Duration) (*domain.CloudKeystore, error) {
	deadline := time.Now().Add(timeout)
	for {
		keystores, err := manager.ListCloudKeystores(domain.GetCloudKeystoreRequest{CloudKeystoreID: &keystoreID})
		if err != nil {
			return nil, err
		}
		if len(keystores) != 1 {
			return nil, fmt.Errorf("could not find cloud keystore with ID %s", keystoreID)
		}

		discovery := keystores[0].Discovery
		if discovery != nil && isNewDiscovery(previous, discovery) {
			logf("Discovery status: %s", discovery.Status)
			if discovery.Status.IsFinished() {
				return &keystores[0], nil
			}
		}

		if time.Now().Add(discoveryPollInterval).After(deadline) {
			return nil, fmt.Errorf("timed out after %s waiting for the discovery on cloud keystore with ID %s to finish. "+
				"It is still running; check on it with \"vcert cloudkeystore get\"", timeout, keystoreID)
		}
		time.Sleep(discoveryPollInterval)
	}
}

func isNewDiscovery(previous *domain.CloudDiscovery, current *domain.CloudDiscovery) bool {
	if previous == nil || previous.Status == domain.CloudDiscoveryStatusNeverInitiated {
		return true
	}
	if current.ID != previous.ID {
		return true
	}
	return current.StartTime != nil && (previous.StartTime == nil || current.StartTime.After(*previous.StartTime))
}

func doCommandCloudKeystoreAbortDiscovery(c *cli.Context) error {
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
	if err := manager.AbortCloudDiscovery(keystore.ID); err != nil {
		return err
	}
	return writeCloudManagementResult(discoveryAbortedOutput{KeystoreID: keystore.ID, KeystoreName: keystore.Name, Aborted: true})
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

	request := domain.ListCloudMachineIdentitiesRequest{KeystoreID: keystore.ID}
	if flags.newlyDiscovered {
		newlyDiscovered := true
		request.NewlyDiscovered = &newlyDiscovered
	}
	identities, err := manager.ListMachineIdentities(request)
	if err != nil {
		return err
	}

	result := make(machineIdentityListOutput, 0, len(identities))
	for _, mi := range identities {
		result = append(result, newMachineIdentityOutput(mi))
	}
	return writeCloudManagementResult(result)
}
