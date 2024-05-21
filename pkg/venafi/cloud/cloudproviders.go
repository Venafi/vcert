package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/httputils"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/webclient/cloudproviders"
)

type CloudKeystoreProvisioningResult struct {
	Arn                        string `json:"arn"`
	CloudProviderCertificateID string `json:"cloudProviderCertificateId"`
	CloudCertificateName       string `json:"cloudProviderCertificateName"`
	CloudCertificateVersion    string `json:"cloudProviderCertificateVersion"`
	Error                      error  `json:"error"`
}

type CloudProvisioningMetadata struct {
	awsMetadata   CloudAwsMetadata
	azureMetadata CloudAzureMetadata
	gcpMetadata   CloudGcpMetadata
}

func (cpm *CloudProvisioningMetadata) GetAWSCertificateMetadata() endpoint.AWSCertificateMetadata {
	return &cpm.awsMetadata
}

func (cpm *CloudProvisioningMetadata) GetAzureCertificateMetadata() endpoint.AzureCertificateMetadata {
	return &cpm.azureMetadata
}

func (cpm *CloudProvisioningMetadata) GetGCPCertificateMetadata() endpoint.GCPCertificateMetadata {
	return &cpm.gcpMetadata
}

type CloudAwsMetadata struct {
	result CloudKeystoreProvisioningResult
}

func (cawm *CloudAwsMetadata) GetARN() string {
	return cawm.result.Arn
}

type CloudGcpMetadata struct {
	result CloudKeystoreProvisioningResult
}

func (cgm *CloudGcpMetadata) GetID() string {
	return cgm.result.CloudProviderCertificateID
}

func (cgm *CloudGcpMetadata) GetName() string {
	return cgm.result.CloudCertificateName
}

type CloudAzureMetadata struct {
	result CloudKeystoreProvisioningResult
}

func (cam *CloudAzureMetadata) GetName() string {
	return cam.result.CloudCertificateName
}

func (cam *CloudAzureMetadata) GetVersion() string {
	return cam.result.CloudCertificateVersion
}

func (cam *CloudAzureMetadata) GetID() string {
	return cam.result.CloudProviderCertificateID
}

// GCMCertificateScope Indicates the Scope for a certificate provisioned to GCP Certificate Manager
type GCMCertificateScope string

const (
	// GCMCertificateScopeDefault Certificates with default scope are served from core Google data centers.
	// If unsure, choose this option.
	GCMCertificateScopeDefault GCMCertificateScope = "DEFAULT"
	// GCMCertificateScopeEdgeCache Certificates with scope EDGE_CACHE are special-purposed certificates,
	// served from Edge Points of Presence.
	// See https://cloud.google.com/vpc/docs/edge-locations.
	GCMCertificateScopeEdgeCache GCMCertificateScope = "EDGE_CACHE"
)

type CertificateTagOption struct {
	Name  string
	Value string
}

type CloudProvisioningAzureOptions struct {
	Name       *string
	Enabled    *bool
	Exportable *bool
	Reusekey   *bool
	Tags       []*CertificateTagOption
}

func (cpao CloudProvisioningAzureOptions) GetType() string {
	return "AKV"
}

type CloudProvisioningGCPOptions struct {
	ID          *string
	Description *string
	Scope       *GCMCertificateScope
	Labels      []*CertificateTagOption
}

func (cpgo CloudProvisioningGCPOptions) GetType() string {
	return "GCM"
}

func setProvisioningOptions(options *endpoint.ProvisioningOptions) (*cloudproviders.CertificateProvisioningOptionsInput, error) {
	var cloudOptions *cloudproviders.CertificateProvisioningOptionsInput
	if options == nil {
		return nil, fmt.Errorf("options for provisioning cannot be null when trying to set them")
	}
	dataOptions, err := json.Marshal(options)
	if err != nil {
		return nil, err
	}

	graphqlAzureOptions := &cloudproviders.CertificateProvisioningAzureOptionsInput{}
	graphqlGCPOptions := &cloudproviders.CertificateProvisioningGCPOptionsInput{}

	if options != nil {
		switch (*options).GetType() {
		case string(cloudproviders.CloudKeystoreTypeAcm):
			// nothing
		case string(cloudproviders.CloudKeystoreTypeAkv):
			err = json.Unmarshal(dataOptions, graphqlAzureOptions)
			if err != nil {
				return nil, err
			}
		case string(cloudproviders.CloudKeystoreTypeGcm):
			err = json.Unmarshal(dataOptions, graphqlGCPOptions)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unknown cloud keystore type: %s", (*options).GetType())
		}
	}

	cloudOptions = &cloudproviders.CertificateProvisioningOptionsInput{
		AwsOptions:   nil,
		AzureOptions: graphqlAzureOptions,
		GcpOptions:   graphqlGCPOptions,
	}
	return cloudOptions, nil
}

func (c *Connector) validateIfCertIsVCPGeneratedByID(certificateId string) error {
	cert, err := c.getCertificates(certificateId)
	if err != nil {
		return fmt.Errorf("error trying to get certificate details for cert with ID: %s, error: %s", certificateId, err.Error())
	}
	if cert.DekHash == "" {
		return fmt.Errorf("error trying to provisioning certificate with ID: %s. Provided certificate is not VCP generated", certificateId)
	}
	return nil
}

func (c *Connector) getGraphqlClient() graphql.Client {
	graphqlURL := c.getURL(urlGraphql)

	// We provide every type of auth here.
	// The logic to decide which auth is inside struct's function: RoundTrip
	httpclient := &http.Client{
		Transport: &httputils.AuthedTransportApi{
			ApiKey:      c.apiKey,
			AccessToken: c.accessToken,
			Wrapped:     http.DefaultTransport,
		},
		Timeout: 30 * time.Second,
	}

	client := graphql.NewClient(graphqlURL, httpclient)
	return client
}

func (c *Connector) getGraphqlHTTPClient() *http.Client {
	// We provide every type of auth here.
	// The logic to decide which auth is inside struct's function: RoundTrip
	httpclient := &http.Client{
		Transport: &httputils.AuthedTransportApi{
			ApiKey:      c.apiKey,
			AccessToken: c.accessToken,
			Wrapped:     http.DefaultTransport,
			UserAgent:   util.DefaultUserAgent,
		},
		Timeout: 30 * time.Second,
	}
	return httpclient
}

func (c *Connector) GetCloudProviderByName(name string) (*domain.CloudProvider, error) {
	if name == "" {
		return nil, fmt.Errorf("cloud provider name cannot be empty")
	}

	cloudProvider, err := c.cloudProvidersClient.GetCloudProviderByName(context.Background(), name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Provider with name %s: %w", name, err)
	}
	if cloudProvider == nil {
		return nil, fmt.Errorf("could not find Cloud Provider with name %s", name)
	}
	return cloudProvider, nil
}

func (c *Connector) GetCloudKeystoreByName(cloudProviderID string, cloudKeystoreName string) (*domain.CloudKeystore, error) {
	if cloudProviderID == "" {
		return nil, fmt.Errorf("cloud provider ID cannot be empty")
	}
	if cloudKeystoreName == "" {
		return nil, fmt.Errorf("cloud keystore name cannot be empty")
	}

	request := domain.GetCloudKeystoreRequest{
		CloudProviderID:   &cloudProviderID,
		CloudProviderName: nil,
		CloudKeystoreID:   nil,
		CloudKeystoreName: &cloudKeystoreName,
	}

	cloudKeystore, err := c.cloudProvidersClient.GetCloudKeystore(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Keystore with name %s from Cloud Provider with ID %s: %w", cloudKeystoreName, cloudProviderID, err)
	}
	if cloudKeystore == nil {
		return nil, fmt.Errorf("could not find Cloud Keystore with name %s in Cloud Provider with ID %s", cloudKeystoreName, cloudProviderID)
	}
	return cloudKeystore, nil
}

func (c *Connector) GetCloudKeystore(request domain.GetCloudKeystoreRequest) (*domain.CloudKeystore, error) {
	cloudKeystore, err := c.cloudProvidersClient.GetCloudKeystore(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Keystore: %w", err)
	}
	if cloudKeystore == nil {
		msg := util.GetKeystoreOptionsString(request.CloudProviderID, request.CloudKeystoreID, request.CloudProviderName, request.CloudKeystoreName)
		return nil, fmt.Errorf("could not find Cloud Keystore with %s: %w", msg, err)
	}
	return cloudKeystore, nil
}

func getCloudMetadataFromWebsocketResponse(respMap interface{}, keystoreType string, keystoreId string) (*CloudProvisioningMetadata, error) {

	val := CloudKeystoreProvisioningResult{}
	valJs, err := json.Marshal(respMap)
	if err != nil {
		return nil, fmt.Errorf("unable to encode response data! Error: %s", err.Error())
	}
	err = json.Unmarshal(valJs, &val)
	if err != nil {
		return nil, fmt.Errorf("unable to parse response data! Error: %s", err.Error())
	}
	if val.Error != nil {
		return nil, fmt.Errorf("unable to provision certificate! Error: %s", val.Error)
	}

	if val.CloudProviderCertificateID == "" {
		return nil, fmt.Errorf("provisioning is not successful, certificate ID from response is empty")
	}

	cloudMetadata := &CloudProvisioningMetadata{}
	switch keystoreType {
	case string(cloudproviders.CloudKeystoreTypeAcm):
		cloudMetadata.awsMetadata.result = val
	case string(cloudproviders.CloudKeystoreTypeAkv):
		cloudMetadata.azureMetadata.result = val
	case string(cloudproviders.CloudKeystoreTypeGcm):
		cloudMetadata.gcpMetadata.result = val
	default:
		err = fmt.Errorf("unknown type %v for keystore with ID: %s", keystoreType, keystoreId)
		return nil, err
	}
	return cloudMetadata, err
}
