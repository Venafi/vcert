package main

import (
	"fmt"
	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/venafi/cloud"
	"log"
	"os"
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

	userAgent := fmt.Sprintf("%s/%s %s", name, version, util.DefaultUserAgent)
	config := &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       url,
		Zone:          zone,
		Credentials:   &endpoint.Authentication{APIKey: os.Getenv(vcpApiKey)},
		UserAgent:     &userAgent,
	}

	connector, err := vcert.NewClient(config)
	if err != nil {
		log.Fatalf("error creating client: %s", err.Error())
	}

	certificateId := "<insert Certificate ID here>"
	keystoreId := "<insert Keystore ID here>"
	googleCertName := "<insert google cert name>" // e.g. test2-venafi-com

	// The Id is the Certificate name for Google, hence we send it as name
	options := &cloud.CloudProvisioningGCPOptions{
		Id: &googleCertName,
	}

	optionsInput := endpoint.ProvisioningOptions(options)

	certMetaData, err := connector.ProvisionCertificate(certificateId, nil, nil, &keystoreId, &optionsInput)
	if err != nil {
		log.Fatalf("error provisioning: %s", err.Error())
	}

	log.Printf("Certificate AWS Metadata:\n%v", certMetaData.GetAwsMetadata())
	log.Printf("Certificate Azure Metadata:\n%v", certMetaData.GetAzureMetadata())
	log.Printf("Certificate GCP Metadata:\n%v", certMetaData.GetGcpMetadata())
}
