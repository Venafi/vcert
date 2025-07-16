package caaccounts

import (
	"context"
	"github.com/Venafi/vcert/v5/pkg/domain"
	"net/http"

	"github.com/Khan/genqlient/graphql"
)

//go:generate go run -mod=mod github.com/Khan/genqlient genqlient.yaml

type CAAccountsClient struct {
	graphqlClient graphql.Client
}

func NewCAAccountsClient(url string, httpClient *http.Client) *CAAccountsClient {
	return &CAAccountsClient{
		graphqlClient: graphql.NewClient(url, httpClient),
	}
}

// ListCAAccounts return a map containing the CAAccounts in the way CAAccountName<key> and domain.CAAccount<value>
func (c *CAAccountsClient) ListCAAccounts(ctx context.Context) (map[string]domain.CAAccount, error) {
	listCAAccountsResponse, err := ListCAAccounts(ctx, c.graphqlClient)

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
