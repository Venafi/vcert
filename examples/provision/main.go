package main

import (
	"log"
	"os"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
)

const (
	vcpURL       = "VCP_URL"
	vcpZone      = "VCP_ZONE"
	vcpApiKey    = "CLOUD_APIKEY"
	envVarNotSet = "environment variable not set: %s"

	name    = "example-provisioning"
	version = "v0.0.1"
)

func main() {

	// URL can be nil if using production TLSPC
	url := os.Getenv(vcpURL)

	zone, found := os.LookupEnv(vcpZone)
	if !found {
		log.Fatalf(envVarNotSet, vcpZone)
	}

	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       url,
		Zone:          zone,
		Credentials:   &endpoint.Authentication{APIKey: os.Getenv(vcpApiKey)},
	}

	connector, err := vcert.NewClient(config)
	if err != nil {
		log.Fatalf("error creating client: %s", err.Error())
	}

	certificateID := "<insert Certificate ID here>"
	keystoreID := "<insert Keystore ID here>"
	certName := "<insert google cert name>" // e.g. test2-venafi-com

	// The ID is the Certificate name for Google, hence we send it as name
	optionsGcp := &cloud.CloudProvisioningGCPOptions{
		ID: &certName,
	}

	optionsInput := endpoint.ProvisioningOptions(optionsGcp)

	// Example for Azure Options
	//optionsAzure := &cloud.CloudProvisioningAzureOptions{
	//	Name: &certName,
	//}
	//
	//optionsInput := endpoint.ProvisioningOptions(optionsAzure)

	req := &endpoint.ProvisioningRequest{
		CertificateID: &certificateID,
		KeystoreID:    &keystoreID,
	}

	certMetaData, err := connector.ProvisionCertificate(req, &optionsInput)
	if err != nil {
		log.Fatalf("error provisioning: %s", err.Error())
	}

	log.Printf("Certificate AWS Metadata ARN:\n%v", certMetaData.GetAWSCertificateMetadata().GetARN())
	log.Printf("Certificate Azure Metadata ID:\n%v", certMetaData.GetAzureCertificateMetadata().GetID())
	log.Printf("Certificate Azure Metadata Name:\n%v", certMetaData.GetAzureCertificateMetadata().GetName())
	log.Printf("Certificate Azure Metadata Version:\n%v", certMetaData.GetAzureCertificateMetadata().GetVersion())
	log.Printf("Certificate GCP Metadata ID:\n%v", certMetaData.GetGCPCertificateMetadata().GetID())
	log.Printf("Certificate GCP Metadata Name:\n%v", certMetaData.GetGCPCertificateMetadata().GetName())
}
