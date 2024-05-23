package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
)

var (
	subCommandCloudKeystore = &cli.Command{
		Name:  subCommandCloudKeystoreName,
		Flags: provisionFlags,
		Usage: "provision certificate from Venafi Platform to Cloud Keystore",
		UsageText: `vcert provision cloudkeystore <Required Venafi Control Plane> <Options>

   vcert provision cloudkeystore --platform vcp -k <VCP API key> --certificate-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx --keystore-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx --format json
   vcert provision cloudkeystore --platform vcp -k <VCP API key> --pickup-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx --provider-name "My GCP Provider"--keystore-name "My GCP provider" --certificate-name "example-venafi-com"
   vcert provision cloudkeystore -p vcp -t <VCP access token> --certificate-id xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx --provider-name "My GCP Provider" --keystore-name "My GCP provider" --file "/path/to/file.txt"`,
		Action: doCommandProvisionCloudKeystore,
	}
)

func doCommandProvisionCloudKeystore(c *cli.Context) error {
	err := validateProvisionFlags(c.Command.Name)
	if err != nil {
		return err
	}
	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, &flags)
	if err != nil {
		return fmt.Errorf("failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg)
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	var req = &endpoint.ProvisioningRequest{}
	var options *endpoint.ProvisioningOptions

	log.Printf("fetching keystore information for provided keystore information from flags. KeystoreID: %s, KeystoreName: %s, ProviderName: %s", flags.keystoreID, flags.keystoreName, flags.providerName)
	getKeystoreReq := buildGetCloudKeystoreRequest(&flags)
	cloudKeystore, err := connector.(*cloud.Connector).GetCloudKeystore(getKeystoreReq)
	if err != nil {
		return err
	}
	log.Printf("successfully fetched keystore")

	if flags.pickupIDFile != "" {
		bytes, err := os.ReadFile(flags.pickupIDFile)
		if err != nil {
			return fmt.Errorf("failed to read Pickup ID value: %s", err)
		}
		flags.pickupID = strings.TrimSpace(string(bytes))
	}

	req, options = fillProvisioningRequest(req, *cloudKeystore, &flags)

	metadata, err := connector.ProvisionCertificate(req, options)
	if err != nil {
		return err
	}

	result := ProvisioningResult{}
	switch cloudKeystore.Type {
	case cloud.KeystoreTypeACM:
		result.ARN = metadata.GetAWSCertificateMetadata().GetARN()
	case cloud.KeystoreTypeAKV:
		result.AzureID = metadata.GetAzureCertificateMetadata().GetID()
		result.AzureName = metadata.GetAzureCertificateMetadata().GetName()
		result.AzureVersion = metadata.GetAzureCertificateMetadata().GetVersion()
	case cloud.KeystoreTypeGCM:
		result.GcpID = metadata.GetGCPCertificateMetadata().GetID()
		result.GcpName = metadata.GetGCPCertificateMetadata().GetName()
	}

	result.MachineIdentityId = metadata.GetMachineIdentityMetadata().GetID()
	result.MachineIdentityActionType = metadata.GetMachineIdentityMetadata().GetActionType()

	err = result.Flush(flags.format)

	if err != nil {
		return fmt.Errorf("failed to output the results: %s", err)
	}
	return nil
}
