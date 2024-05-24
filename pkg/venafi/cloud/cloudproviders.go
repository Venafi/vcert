package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Khan/genqlient/graphql"
	"github.com/google/uuid"

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
	MachineIdentityActionType  string `json:"machineIdentityActionType"`
	MachineIdentityId          string `json:"machineIdentityId"`
	Error                      error  `json:"error"`
}

const (
	KeystoreTypeACM = "ACM"
	KeystoreTypeAKV = "AKV"
	KeystoreTypeGCM = "GCM"
)

type CloudProvisioningMetadata struct {
	awsMetadata     CloudAwsMetadata
	azureMetadata   CloudAzureMetadata
	gcpMetadata     CloudGcpMetadata
	machineMetadata MachineIdentityMetadata
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

func (cpm *CloudProvisioningMetadata) GetMachineIdentityMetadata() endpoint.MachineIdentityMetadata {
	return &cpm.machineMetadata
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

type MachineIdentityMetadata struct {
	result CloudKeystoreProvisioningResult
}

func (mim *MachineIdentityMetadata) GetID() string {
	return mim.result.MachineIdentityId
}

func (mim *MachineIdentityMetadata) GetActionType() string {
	return mim.result.MachineIdentityActionType
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
	return KeystoreTypeAKV
}

type CloudProvisioningGCPOptions struct {
	ID          *string
	Description *string
	Scope       *GCMCertificateScope
	Labels      []*CertificateTagOption
}

func (cpgo CloudProvisioningGCPOptions) GetType() string {
	return KeystoreTypeGCM
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
	// The logic to decide which auth to use is inside struct's function: RoundTrip
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

func (c *Connector) ProvisionCertificate(req *endpoint.ProvisioningRequest, options *endpoint.ProvisioningOptions) (provisioningMetadata endpoint.ProvisioningMetadata, err error) {
	log.Printf("Starting Provisioning Flow")

	if req == nil {
		return nil, fmt.Errorf("missing Provisioning Request")
	}

	reqData := *req

	if reqData.Timeout <= 0 {
		reqData.Timeout = util.DefaultTimeout * time.Second
	}

	if reqData.CertificateID == nil {
		if reqData.PickupID == nil {
			return nil, fmt.Errorf("no Certificate ID or Pickup ID were provided for provisioning")
		}
		log.Printf("Certificate ID was not provided in request. Fetching it by using Pickup ID %s", *(reqData.PickupID))
		certID, err := c.getCertIDFromPickupID(*(reqData.PickupID), reqData.Timeout)
		if err != nil {
			return nil, err
		}
		reqData.CertificateID = certID
	}
	certificateIDString := *(reqData.CertificateID)
	log.Printf("Certificate ID for provisioning: %s", certificateIDString)

	// Is certificate generated by VCP?
	log.Printf("Validating if certificate is generated by VCP")
	err = c.validateIfCertIsVCPGeneratedByID(*(reqData.CertificateID))
	if err != nil {
		return nil, err
	}
	log.Println("Certificate is valid for provisioning (VCP generated)")

	// setting options for provisioning
	var provisioningOptions *cloudproviders.CertificateProvisioningOptionsInput
	if options != nil {
		log.Println("setting provisioning options")
		provisioningOptions, err = setProvisioningOptions(options)
		if err != nil {
			return nil, err
		}
		log.Println("provisioning options successfully set")
	}

	ctx := context.Background()

	var keystoreIDString string

	if reqData.Keystore == nil {
		if reqData.KeystoreID == nil {
			if reqData.ProviderName == nil || reqData.KeystoreName == nil {
				return nil, fmt.Errorf("any of keystore object, keystore ID or both Provider Name and Keystore Name must be provided for provisioning")
			}
		}

		// Getting Keystore to find type
		keystoreIDInput := util.StringPointerToString(reqData.KeystoreID)
		keystoreNameInput := util.StringPointerToString(reqData.KeystoreName)
		providerNameInput := util.StringPointerToString(reqData.ProviderName)

		log.Printf("fetching keystore information for provided keystore information. KeystoreID: %s, KeystoreName: %s, ProviderName: %s", keystoreIDInput, keystoreNameInput, providerNameInput)
		cloudKeystore, err := c.GetCloudKeystore(domain.GetCloudKeystoreRequest{
			CloudProviderID:   nil,
			CloudProviderName: req.ProviderName,
			CloudKeystoreID:   req.KeystoreID,
			CloudKeystoreName: req.KeystoreName,
		})
		if err != nil {
			return nil, err
		}

		keystoreIDString = cloudKeystore.ID

		log.Printf("successfully fetched keystore information for KeystoreID: %s", keystoreIDString)
	} else {
		log.Printf("Keystore was provided")
		keystoreIDString = reqData.Keystore.ID
	}
	log.Printf("Keystore ID for provisioning: %s", keystoreIDString)
	wsClientID := uuid.New().String()

	wsConn, err := c.notificationSvcClient.Subscribe(wsClientID)
	if err != nil {
		return nil, err
	}

	log.Printf("Provisioning Certificate ID %s for Keystore %s", certificateIDString, keystoreIDString)
	_, err = c.cloudProvidersClient.ProvisionCertificate(ctx, certificateIDString, keystoreIDString, wsClientID, provisioningOptions)
	if err != nil {
		return nil, err
	}

	ar, err := c.notificationSvcClient.ReadResponse(wsConn)
	if err != nil {
		return nil, err
	}

	// parsing metadata from websocket response
	log.Printf("Getting Cloud Metadata of Certificate ID %s and Keystore ID: %s", certificateIDString, keystoreIDString)
	cloudMetadata, err := getCloudMetadataFromWebsocketResponse(ar.Data.Result)
	if err != nil {
		return nil, err
	}
	log.Printf("Successfully got Cloud Metadata for Certificate ID %s and Keystore ID: %s", certificateIDString, keystoreIDString)

	log.Printf("Successfully finished Provisioning Flow for Certificate ID %s and Keystore ID %s", certificateIDString, keystoreIDString)
	return cloudMetadata, nil
}

func (c *Connector) ProvisionCertificateToMachineIdentity(req endpoint.ProvisioningRequest) (endpoint.ProvisioningMetadata, error) {
	log.Printf("Starting Provisioning to Machine Identity Flow")

	if req.MachineIdentityID == nil {
		return nil, fmt.Errorf("error trying to provision certificate to machine identity: machineIdentityID is nil")
	}

	machineIdentityID := *req.MachineIdentityID
	certificateID := ""
	timeout := util.DefaultTimeout * time.Second
	if req.Timeout != 0 {
		timeout = req.Timeout
	}

	if req.CertificateID == nil {
		if req.PickupID == nil {
			return nil, fmt.Errorf("no Certificate ID or Pickup ID were provided for provisioning")
		}

		log.Printf("Certificate ID was not provided in request. Using Pickup ID %s to fetch it", *req.PickupID)
		certID, err := c.getCertIDFromPickupID(*req.PickupID, timeout)
		if err != nil {
			return nil, err
		}
		certificateID = *certID
	} else {
		certificateID = *req.CertificateID
	}

	log.Printf("certificate ID for provisioning: %s", certificateID)

	// Is certificate generated by VCP?
	log.Printf("validating if certificate is generated by VCP")
	err := c.validateIfCertIsVCPGeneratedByID(certificateID)
	if err != nil {
		return nil, err
	}
	log.Println("Certificate is VCP generated")

	ctx := context.Background()
	wsClientID := uuid.New().String()

	wsConn, err := c.notificationSvcClient.Subscribe(wsClientID)
	if err != nil {
		return nil, err
	}

	log.Printf("Provisioning Certificate with ID %s to Machine Identity with ID %s", certificateID, machineIdentityID)
	_, err = c.cloudProvidersClient.ProvisionCertificateToMachineIdentity(ctx, &certificateID, machineIdentityID, wsClientID)
	if err != nil {
		return nil, err
	}

	ar, err := c.notificationSvcClient.ReadResponse(wsConn)
	if err != nil {
		return nil, err
	}

	// parsing metadata from websocket response
	log.Printf("Getting Cloud Metadata of Machine Identity with ID: %s", machineIdentityID)
	cloudMetadata, err := getCloudMetadataFromWebsocketResponse(ar.Data.Result)
	if err != nil {
		return nil, err
	}
	log.Printf("Successfully retrieved Cloud Metadata for Machine Identity with ID: %s", machineIdentityID)

	log.Printf("Successfully completed Provisioning Flow for Certificate ID %s and Machine Identity ID %s", certificateID, machineIdentityID)
	return cloudMetadata, nil
}

func (c *Connector) GetCloudProvider(request domain.GetCloudProviderRequest) (*domain.CloudProvider, error) {
	cloudProvider, err := c.cloudProvidersClient.GetCloudProvider(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Provider with name %s: %w", request.Name, err)
	}
	if cloudProvider == nil {
		return nil, fmt.Errorf("could not find Cloud Provider with name %s", request.Name)
	}
	return cloudProvider, nil
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

func (c *Connector) GetMachineIdentity(request domain.GetCloudMachineIdentityRequest) (*domain.CloudMachineIdentity, error) {
	if request.MachineIdentityID == nil {
		return nil, fmt.Errorf("machine identity ID cannot be empty")
	}

	machineIdentity, err := c.cloudProvidersClient.GetMachineIdentity(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Machine Identity with ID %s: %w", *request.MachineIdentityID, err)
	}
	if machineIdentity == nil {
		return nil, fmt.Errorf("could not find Cloud Machine Identity with ID %s", *request.MachineIdentityID)
	}
	return machineIdentity, nil
}

func (c *Connector) DeleteMachineIdentity(id uuid.UUID) (bool, error) {
	if id == uuid.Nil {
		return false, fmt.Errorf("invalid machine identity ID: %s", id)
	}
	deleted, err := c.cloudProvidersClient.DeleteMachineIdentity(context.Background(), id.String())
	if err != nil {
		return false, fmt.Errorf("failed to delete machine identity with ID %s: %w", id, err)
	}
	return deleted, nil
}

func getCloudMetadataFromWebsocketResponse(resultMap interface{}) (*CloudProvisioningMetadata, error) {

	result := CloudKeystoreProvisioningResult{}
	resultBytes, err := json.Marshal(resultMap)
	if err != nil {
		return nil, fmt.Errorf("unable to encode response data: %w", err)
	}
	err = json.Unmarshal(resultBytes, &result)
	if err != nil {
		return nil, fmt.Errorf("unable to parse response data: %w", err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("unable to provision certificate: %w", result.Error)
	}
	if result.CloudProviderCertificateID == "" {
		return nil, fmt.Errorf("provisioning failed, certificate ID from response is empty")
	}

	cloudMetadata := &CloudProvisioningMetadata{
		machineMetadata: MachineIdentityMetadata{
			result: result,
		},
	}

	// Only ACM returns an ARN value
	if result.Arn != "" {
		cloudMetadata.awsMetadata.result = result
	} else if result.CloudCertificateVersion != "" {
		// Only Azure returns a certificate version value
		cloudMetadata.azureMetadata.result = result
	} else {
		// No ARN and no certificate version, default to GCM
		cloudMetadata.gcpMetadata.result = result
	}

	return cloudMetadata, err
}
