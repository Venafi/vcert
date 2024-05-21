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
	commandProvision = &cli.Command{
		Before: runBeforeCommand,
		Name:   commandProvisionName,
		Usage:  "To provision a certificate",
		UsageText: ` vcert provision <Required Venafi Control Plane> <Options>

		vcert provision cloudkeystore -k <VCP API key>
		vcert provision cloudkeystore -k <VCP API key>
		vcert provision cloudkeystore -p vcp -t <VCP access token>`,
		Subcommands: []*cli.Command{
			{
				Name:      subCommandCloudKeystore,
				Flags:     provisionFlags,
				Usage:     "set Cloud Keystore for provision",
				UsageText: `vcert provision cloudkeystore`,
				Action:    doCommandProvision,
			},
		},
	}
)

func doCommandProvision(c *cli.Context) error {
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
		return fmt.Errorf("Failed to build vcert config: %s", err)
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

	arn := metadata.GetAWSCertificateMetadata().GetARN()
	azureID := metadata.GetAzureCertificateMetadata().GetID()
	azureName := metadata.GetAzureCertificateMetadata().GetName()
	azureVersion := metadata.GetAzureCertificateMetadata().GetVersion()
	gcpID := metadata.GetGCPCertificateMetadata().GetID()
	gcpName := metadata.GetGCPCertificateMetadata().GetName()

	result := &ProvisioningResult{
		ARN:          &arn,
		AzureID:      &azureID,
		AzureName:    &azureName,
		AzureVersion: &azureVersion,
		GcpID:        &gcpID,
		GcpName:      &gcpName,
	}

	err = result.Flush(flags.format)

	if err != nil {
		return fmt.Errorf("failed to output the results: %s", err)
	}
	return nil
}
