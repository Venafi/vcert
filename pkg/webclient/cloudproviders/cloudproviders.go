package cloudproviders

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Khan/genqlient/graphql"

	"github.com/Venafi/vcert/v5/pkg/domain"
)

//go:generate go run -mod=mod github.com/Khan/genqlient genqlient.yaml

type CloudProvidersClient struct {
	graphqlClient graphql.Client
}

func NewCloudProvidersClient(url string, httpClient *http.Client) *CloudProvidersClient {
	return &CloudProvidersClient{
		graphqlClient: graphql.NewClient(url, httpClient),
	}
}

func (c *CloudProvidersClient) GetCloudProviderByName(ctx context.Context, name string) (*domain.CloudProvider, error) {
	if name == "" {
		return nil, fmt.Errorf("cloud provider name cannot be empty")
	}
	resp, err := GetCloudProviderByName(ctx, c.graphqlClient, name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Cloud Provider with name %s: %w", name, err)
	}
	if resp == nil || resp.GetCloudProviders() == nil || len(resp.GetCloudProviders().Nodes) != 1 {
		return nil, fmt.Errorf("could not find Cloud Provider with name %s", name)
	}

	cp := resp.GetCloudProviders().Nodes[0]

	statusDetails := ""
	if cp.GetStatusDetails() != nil {
		statusDetails = *cp.GetStatusDetails()
	}

	return &domain.CloudProvider{
		ID:             cp.GetId(),
		Name:           cp.GetName(),
		Type:           string(cp.GetType()),
		Status:         string(cp.GetStatus()),
		StatusDetails:  statusDetails,
		KeystoresCount: cp.GetKeystoresCount(),
	}, nil
}
