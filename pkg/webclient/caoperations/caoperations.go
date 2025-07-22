package caoperations

import (
	"context"
	"net/http"

	"github.com/Khan/genqlient/graphql"

	"github.com/Venafi/vcert/v5/pkg/webclient/caoperations/service"
)

//go:generate go run -mod=mod github.com/Khan/genqlient genqlient.yaml

type CAOperationsClient struct {
	caOperationsService service.CAOperationsServiceWrapper
}

func NewCAOperationsClient(url string, httpClient *http.Client) *CAOperationsClient {
	return &CAOperationsClient{
		caOperationsService: &CAOperationsService{
			graphqlClient: graphql.NewClient(url, httpClient),
		},
	}
}

func (c *CAOperationsClient) SetCAOperationsService(caOperationsService service.CAOperationsServiceWrapper) {
	c.caOperationsService = caOperationsService
}

func (c *CAOperationsClient) RevokeCertificate(ctx context.Context, fingerprint string, certificateAuthorityAccountId *string, revocationReason service.RevocationReason, revocationComment *string) (*service.RevokeCertificateRequestResponse, error) {
	return c.caOperationsService.RevokeCertificateRequest(ctx, fingerprint, certificateAuthorityAccountId, revocationReason, revocationComment)
}

type CAOperationsService struct {
	graphqlClient graphql.Client
}

func (ca *CAOperationsService) RevokeCertificateRequest(ctx context.Context, fingerprint string, certificateAuthorityAccountId *string, revocationReason service.RevocationReason, revocationComment *string) (*service.RevokeCertificateRequestResponse, error) {
	return service.RevokeCertificateRequest(ctx, ca.graphqlClient, fingerprint, certificateAuthorityAccountId, revocationReason, revocationComment)
}
