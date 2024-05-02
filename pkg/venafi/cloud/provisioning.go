package cloud

import (
	"github.com/Venafi/vcert/v5/pkg/endpoint"
)

type CloudKeystoreProvisioningResult struct {
	Arn                        string `json:"arn"`
	CloudProviderCertificateId string `json:"cloudProviderCertificateId"`
	Error                      error  `json:"error"`
}

type CloudProvisioningMetadata struct {
	awsMetadata   CloudAwsMetadata
	azureMetadata CloudAzureMetadata
	gcpMetadata   CloudGcpMetadata
}

func (cpm *CloudProvisioningMetadata) GetAwsMetadata() endpoint.AwsMetadata {
	return &cpm.awsMetadata
}

func (cpm *CloudProvisioningMetadata) GetAzureMetadata() endpoint.AzureMetadata {
	return &cpm.azureMetadata
}

func (cpm *CloudProvisioningMetadata) GetGcpMetadata() endpoint.GcpMetadata {
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

func (cgm *CloudGcpMetadata) GetGCPID() string {
	return cgm.result.CloudProviderCertificateId
}

func (cgm *CloudGcpMetadata) GetCertificateName() string {
	// TODO: fill once we get CertName from workflow result
	return ""
}

type CloudAzureMetadata struct {
	result CloudKeystoreProvisioningResult
}

func (cam *CloudAzureMetadata) GetCertificateName() string {
	// TODO: fill once we get CertName from workflow result
	return ""
}

func (cam *CloudAzureMetadata) GetVersion() string {
	// TODO: fill once we get Version from workflow result
	return ""
}

func (cam *CloudAzureMetadata) GetAKVID() string {
	return cam.result.CloudProviderCertificateId
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
	Id          *string
	Description *string
	Scope       *GCMCertificateScope
	Labels      []*CertificateTagOption
}

func (cpgo CloudProvisioningGCPOptions) GetType() string {
	return "GCM"
}
