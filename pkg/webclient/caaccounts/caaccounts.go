package caaccounts

import (
	"context"
	"net/http"

	"github.com/Khan/genqlient/graphql"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/webclient/caaccounts/service"
)

//go:generate go run -mod=mod github.com/Khan/genqlient genqlient.yaml

type CAAccountsClient struct {
	caAccountsService service.CAAccountsServiceWrapper
}

func NewCAAccountsClient(url string, httpClient *http.Client) *CAAccountsClient {
	return &CAAccountsClient{
		caAccountsService: &CAAccountsService{
			graphqlClient: graphql.NewClient(url, httpClient),
		},
	}
}

func (c *CAAccountsClient) SetCAAccountsService(caAccountsService service.CAAccountsServiceWrapper) {
	c.caAccountsService = caAccountsService
}

// ListCAAccounts return a map containing the CAAccounts in the way CAAccountName<key> and domain.CAAccount<value>
func (c *CAAccountsClient) ListCAAccounts(ctx context.Context) (map[string]domain.CAAccount, error) {
	listCAAccountsResponse, err := c.caAccountsService.ListCAAccounts(ctx)

	if err != nil {
		return nil, err
	}

	caAccounts := make(map[string]domain.CAAccount)

	if listCAAccountsResponse != nil && listCAAccountsResponse.GetCertificateAuthorityAccounts() != nil {
		for _, caAccountData := range listCAAccountsResponse.GetCertificateAuthorityAccounts().GetNodes() {
			if caAccountData != nil {
				caAccounts[caAccountData.GetName()] = domain.CAAccount{
					Id:                       caAccountData.GetId(),
					Name:                     caAccountData.GetName(),
					CertificateAuthorityType: string(caAccountData.GetCertificateAuthorityType()),
				}
			}
		}
	}

	return caAccounts, nil
}

type CAAccountsService struct {
	graphqlClient graphql.Client
}

func (cs *CAAccountsService) ListCAAccounts(ctx context.Context) (*service.ListCAAccountsResponse, error) {
	return service.ListCAAccounts(ctx, cs.graphqlClient)
}
