package caoperations

import (
	"context"
	"net/http"

	"github.com/Khan/genqlient/graphql"
)

//go:generate go run -mod=mod github.com/Khan/genqlient genqlient.yaml

type CAOperationsClient struct {
	graphqlClient graphql.Client
}

func NewCAOperationsClient(url string, httpClient *http.Client) *CAOperationsClient {
	return &CAOperationsClient{
		graphqlClient: graphql.NewClient(url, httpClient),
	}
}

func (c *CAOperationsClient) RevokeCertificate(ctx context.Context, fingerprint string, certificateAuthorityAccountId string, revocationReason RevocationReason, revocationComment string) (*RevokeCertificateRequestResponse, error) {
	return RevokeCertificateRequest(ctx, c.graphqlClient, fingerprint, certificateAuthorityAccountId, revocationReason, revocationComment)
}
