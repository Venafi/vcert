package ngts

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/domain"
	"github.com/Venafi/vcert/v5/pkg/webclient/cloudproviders"
)

func TestCloudManagementRequiresAuthentication(t *testing.T) {
	c := &Connector{}

	if _, err := c.ListCloudProviders(domain.GetCloudProviderRequest{}); err == nil || !strings.Contains(err.Error(), "must be authenticated") {
		t.Fatalf("expected an authentication error, got %v", err)
	}
	if err := c.DeleteCloudKeystore("k1"); err == nil || !strings.Contains(err.Error(), "must be authenticated") {
		t.Fatalf("expected an authentication error, got %v", err)
	}
}

func TestListMachineIdentitiesUsesTheGraphQLClient(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"cloudMachineIdentities":{"nodes":[{"id":"m1","cloudKeystoreId":"k1","status":"INSTALLED","certificateId":"c1"}],"pageInfo":{"hasNextPage":false}}}}`))
	}))
	defer server.Close()

	c := &Connector{cloudProvidersClient: cloudproviders.NewCloudProvidersClient(server.URL, server.Client())}
	identities, err := c.ListMachineIdentities(domain.ListCloudMachineIdentitiesRequest{KeystoreID: "k1"})
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if len(identities) != 1 || identities[0].ID != "m1" || identities[0].Status != domain.MachineIdentityStatusInstalled {
		t.Fatalf("unexpected machine identities: %+v", identities)
	}
	if !strings.Contains(body, `"cloudKeystoreId":"k1"`) {
		t.Fatalf("unexpected request body: %s", body)
	}
}
