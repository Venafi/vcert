package main

import (
	"log"
	"os"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

const (
	vcpURL       = "VCP_URL"
	vcpZone      = "VCP_ZONE"
	vcpApiKey    = "CLOUD_APIKEY"
	envVarNotSet = "environment variable not set: %s"

	name = "example-provisioning"
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

	optionsInput := domain.ProvisioningOptions{
		CloudCertificateName: certName,
	}

	req := &domain.ProvisioningRequest{
		CertificateID: &certificateID,
		KeystoreID:    &keystoreID,
	}

	certMetaData, err := connector.ProvisionCertificate(req, &optionsInput)
	if err != nil {
		log.Fatalf("error provisioning: %s", err.Error())
	}

	// Example to get values from other keystores machine identities metadata
	if certMetaData.CloudKeystoreType == domain.CloudKeystoreTypeACM {
		log.Printf("Certificate AWS Metadata ARN:\n%v", certMetaData.ARN)
	}
	if certMetaData.CloudKeystoreType == domain.CloudKeystoreTypeAKV {
		log.Printf("Certificate Azure Metadata ID:\n%v", certMetaData.CertificateID)
		log.Printf("Certificate Azure Metadata Name:\n%v", certMetaData.CertificateName)
		log.Printf("Certificate Azure Metadata Version:\n%v", certMetaData.CertificateVersion)
	}
	if certMetaData.CloudKeystoreType == domain.CloudKeystoreTypeGCM {
		log.Printf("Certificate GCP Metadata ID:\n%v", certMetaData.CertificateID)
		log.Printf("Certificate GCP Metadata Name:\n%v", certMetaData.CertificateName)
	}
}
