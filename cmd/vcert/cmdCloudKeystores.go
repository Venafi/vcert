package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/domain"
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
	var flagsP *commandFlags
	flagsP, err = gettingIDsFromFiles(&flags)
	if err != nil {
		return err
	}

	err = setTLSConfig()
	if err != nil {
		return err
	}

	cfg, err := buildConfig(c, flagsP)
	if err != nil {
		return fmt.Errorf("failed to build vcert config: %s", err)
	}

	connector, err := vcert.NewClient(&cfg)
	if err != nil {
		logf("Unable to connect to %s: %s", cfg.ConnectorType, err)
	} else {
		logf("Successfully connected to %s", cfg.ConnectorType)
	}

	var req = &domain.ProvisioningRequest{}
	var options *domain.ProvisioningOptions

	log.Printf("fetching keystore information for provided keystore information from flags. KeystoreID: %s, KeystoreName: %s, ProviderName: %s", flags.keystoreID, flags.keystoreName, flags.providerName)
	getKeystoreReq := buildGetCloudKeystoreRequest(flagsP)
	cloudKeystore, err := connector.(*cloud.Connector).GetCloudKeystore(getKeystoreReq)
	if err != nil {
		return err
	}
	log.Printf("successfully fetched keystore")

	req, options = fillProvisioningRequest(req, *cloudKeystore, flagsP)

	metadata, err := connector.ProvisionCertificate(req, options)
	if err != nil {
		return err
	}

	result := ProvisioningResult{
		MachineIdentityId:         metadata.MachineIdentityID,
		MachineIdentityActionType: metadata.MachineIdentityActionType,
	}
	switch metadata.CloudKeystoreType {
	case domain.CloudKeystoreTypeACM:
		result.ARN = metadata.ARN
	case domain.CloudKeystoreTypeAKV:
		result.AzureID = metadata.CertificateID
		result.AzureName = metadata.CertificateName
		result.AzureVersion = metadata.CertificateVersion
	case domain.CloudKeystoreTypeGCM:
		result.GcpID = metadata.CertificateID
		result.GcpName = metadata.CertificateName
	default:
		return fmt.Errorf("unknown keystore metadata type: %s", metadata.CloudKeystoreType)
	}

	err = result.Flush(flags.provisionFormat, flags.provisionOutputFile)
	if err != nil {
		return fmt.Errorf("failed to output the results: %s", err)
	}
	return nil
}

func gettingIDsFromFiles(flags *commandFlags) (*commandFlags, error) {
	if flags.pickupIDFile != "" {
		bytes, err := os.ReadFile(flags.pickupIDFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Pickup ID value: %s", err)
		}
		flags.pickupID = strings.TrimSpace(string(bytes))
	}
	if flags.certificateIDFile != "" {
		bytes, err := os.ReadFile(flags.certificateIDFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read Certificate ID value: %s", err)
		}
		flags.certificateID = strings.TrimSpace(string(bytes))
	}
	return flags, nil
}
