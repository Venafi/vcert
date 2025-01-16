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
	"github.com/Venafi/vcert/v5/pkg/httputils"
	"github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/webclient/cloudproviders"
)

type CloudKeystoreProvisioningResult struct {
	CloudProviderCertificateID string `json:"cloudProviderCertificateId"`
	CloudCertificateName       string `json:"cloudProviderCertificateName"`
	CloudCertificateVersion    string `json:"cloudProviderCertificateVersion"`
	MachineIdentityActionType  string `json:"machineIdentityActionType"`
	MachineIdentityId          string `json:"machineIdentityId"`
	Error                      error  `json:"error"`
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

func (c *Connector) ProvisionCertificate(req *domain.ProvisioningRequest, options *domain.ProvisioningOptions) (*domain.ProvisioningMetadata, error) {
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

	// Is certificate valid for provisioning?
	log.Printf("Validating if certificate is valid")
	err := c.validateCertificate(*(reqData.CertificateID))
	if err != nil {
		return nil, err
	}
	log.Printf("Good certificate for provisioning!")

	cloudKeystore := reqData.Keystore

	if cloudKeystore == nil {
		if reqData.KeystoreID == nil {
			if reqData.ProviderName == nil || reqData.KeystoreName == nil {
				return nil, fmt.Errorf("any of keystore object, keystore ID or both Provider Name and Keystore Name must be provided for provisioning")
			}
		}

		// Getting Keystore to find type
		keystoreIDInput := util.StringPointerToString(reqData.KeystoreID)
		keystoreNameInput := util.StringPointerToString(reqData.KeystoreName)
		providerNameInput := util.StringPointerToString(reqData.ProviderName)

		log.Printf("fetching keystore with KeystoreID: %s, KeystoreName: %s, ProviderName: %s", keystoreIDInput, keystoreNameInput, providerNameInput)
		cloudKeystore, err = c.GetCloudKeystore(domain.GetCloudKeystoreRequest{
			CloudProviderName: req.ProviderName,
			CloudKeystoreID:   req.KeystoreID,
			CloudKeystoreName: req.KeystoreName,
		})
		if err != nil {
			return nil, err
		}

		log.Printf("successfully fetched keystore information")
	}
	log.Printf("Keystore ID for provisioning: %s", cloudKeystore.ID)

	// setting options for provisioning
	var provisioningOptions *cloudproviders.CertificateProvisioningOptionsInput
	if options != nil {
		log.Println("setting provisioning options")
		provisioningOptions, err = setProvisioningOptions(*options, cloudKeystore.Type)
		if err != nil {
			return nil, err
		}
		log.Println("provisioning options successfully set")
	}

	wsClientID := uuid.New().String()
	wsConn, err := c.notificationSvcClient.Subscribe(wsClientID)
	if err != nil {
		return nil, err
	}

	log.Printf("Provisioning Certificate ID %s for Keystore %s", certificateIDString, cloudKeystore.ID)
	_, err = c.cloudProvidersClient.ProvisionCertificate(context.Background(), certificateIDString, cloudKeystore.ID, wsClientID, provisioningOptions)
	if err != nil {
		return nil, err
	}

	workflowResponse, err := c.notificationSvcClient.ReadResponse(wsConn)
	if err != nil {
		return nil, err
	}

	// parsing metadata from websocket response
	log.Printf("Getting Cloud Metadata of Certificate ID %s and Keystore ID: %s", certificateIDString, cloudKeystore.ID)
	cloudMetadata, err := getCloudMetadataFromWebsocketResponse(workflowResponse.Data.Result, cloudKeystore.Type)
	if err != nil {
		return nil, err
	}
	log.Printf("Successfully got Cloud Metadata for Certificate ID %s and Keystore ID: %s", certificateIDString, cloudKeystore.ID)

	log.Printf("Successfully finished Provisioning Flow for Certificate ID %s and Keystore ID %s", certificateIDString, cloudKeystore.ID)
	return cloudMetadata, nil
}

func (c *Connector) ProvisionCertificateToMachineIdentity(req domain.ProvisioningRequest) (*domain.ProvisioningMetadata, error) {
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
	err := c.validateCertificate(certificateID)
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

	var keystoreType domain.CloudKeystoreType
	if req.Keystore == nil {
		log.Printf("fetching machine identity to get type")
		machineIdentity, err := c.cloudProvidersClient.GetMachineIdentity(ctx, domain.GetCloudMachineIdentityRequest{
			MachineIdentityID: req.MachineIdentityID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get machine identity: %w", err)
		}
		log.Printf("successfully fetched machine identity")
		keystoreType = machineIdentity.Metadata.GetKeystoreType()
	} else {
		keystoreType = req.Keystore.Type
	}

	// parsing metadata from websocket response
	log.Printf("Getting Cloud Metadata of Machine Identity with ID: %s", machineIdentityID)
	cloudMetadata, err := getCloudMetadataFromWebsocketResponse(ar.Data.Result, keystoreType)
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

func (c *Connector) DeleteMachineIdentity(machineIdentityID string) (bool, error) {
	if machineIdentityID == "" {
		return false, fmt.Errorf("machine identity ID cannot be nil")
	}
	deleted, err := c.cloudProvidersClient.DeleteMachineIdentity(context.Background(), machineIdentityID)
	if err != nil {
		return false, fmt.Errorf("failed to delete machine identity with ID %s: %w", machineIdentityID, err)
	}
	return deleted, nil
}

func setProvisioningOptions(options domain.ProvisioningOptions, keystoreType domain.CloudKeystoreType) (*cloudproviders.CertificateProvisioningOptionsInput, error) {
	awsOptions := &cloudproviders.CertificateProvisioningAWSOptionsInput{}
	azureOptions := &cloudproviders.CertificateProvisioningAzureOptionsInput{}
	gcpOptions := &cloudproviders.CertificateProvisioningGCPOptionsInput{}

	switch keystoreType {
	case domain.CloudKeystoreTypeACM:
		awsOptions.Arn = &options.ARN
	case domain.CloudKeystoreTypeAKV:
		azureOptions.Name = &options.CloudCertificateName
	case domain.CloudKeystoreTypeGCM:
		gcpOptions.Id = &options.CloudCertificateName
	default:
		return nil, fmt.Errorf("unknown cloud keystore type: %s", keystoreType)
	}

	provisioningOptions := &cloudproviders.CertificateProvisioningOptionsInput{
		AwsOptions:   awsOptions,
		AzureOptions: azureOptions,
		GcpOptions:   gcpOptions,
	}
	return provisioningOptions, nil
}

func (c *Connector) validateCertificate(certificateId string) error {
	cert, err := c.getCertificates(certificateId)
	if err != nil {
		return fmt.Errorf("error trying to get certificate details for cert with ID: %s, error: %s", certificateId, err.Error())
	}

	// Is certificate not expired?
	log.Printf("Validating if certificate is not expired")
	now := time.Now()
	if now.Unix() > cert.ValidityEnd.Unix() {
		return fmt.Errorf("error trying to provisioning certificate with ID: %s. Provided certificate is expired", certificateId)
	}
	log.Printf("Certificate is still valid")

	// Is certificate generated by VCP?
	log.Printf("Validating if certificate is generated by VCP")
	if cert.DekHash == "" {
		return fmt.Errorf("error trying to provisioning certificate with ID: %s. Provided certificate is not VCP generated", certificateId)
	}
	log.Println("Certificate is valid for provisioning (VCP generated)")
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

func getCloudMetadataFromWebsocketResponse(resultMap interface{}, keystoreType domain.CloudKeystoreType) (*domain.ProvisioningMetadata, error) {

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

	cloudMetadata := &domain.ProvisioningMetadata{
		CloudKeystoreType:         keystoreType,
		CertificateID:             result.CloudProviderCertificateID,
		CertificateName:           result.CloudCertificateName,
		CertificateVersion:        result.CloudCertificateVersion,
		MachineIdentityID:         result.MachineIdentityId,
		MachineIdentityActionType: result.MachineIdentityActionType,
	}

	return cloudMetadata, err
}
